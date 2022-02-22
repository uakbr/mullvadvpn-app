use self::config::Config;
#[cfg(not(windows))]
use super::tun_provider;
use super::{tun_provider::TunProvider, TunnelEvent, TunnelMetadata};
use crate::routing::{self, RequiredRoute, RouteManagerHandle};
#[cfg(windows)]
use futures::{channel::mpsc, StreamExt};
use futures::{
	channel::oneshot,
	future::{
		abortable,
		AbortHandle as FutureAbortHandle,
	},
};
#[cfg(target_os = "linux")]
use lazy_static::lazy_static;
#[cfg(target_os = "linux")]
use std::env;
#[cfg(windows)]
use std::io;
use std::{
    net::IpAddr,
    path::Path,
    sync::{mpsc as sync_mpsc, Arc, Mutex},
};
#[cfg(windows)]
use talpid_types::BoxedError;
use talpid_types::{
    ErrorExt,
    net::obfuscation::ObfuscatorConfig,
};
use tunnel_obfuscation::{
    create_obfuscator, Error as ObfuscationError, Settings as ObfuscationSettings, Udp2TcpSettings,
};

/// WireGuard config data-types
pub mod config;
mod connectivity_check;
mod logging;
mod stats;
mod wireguard_go;
#[cfg(target_os = "linux")]
pub(crate) mod wireguard_kernel;
#[cfg(windows)]
mod wireguard_nt;

use self::wireguard_go::WgGoTunnel;

type Result<T> = std::result::Result<T, Error>;

/// Errors that can happen in the Wireguard tunnel monitor.
#[derive(err_derive::Error, Debug)]
#[error(no_from)]
pub enum Error {
    /// Failed to set up routing.
    #[error(display = "Failed to setup routing")]
    SetupRoutingError(#[error(source)] crate::routing::Error),

    /// Tunnel timed out
    #[error(display = "Tunnel timed out")]
    TimeoutError,

    /// An interaction with a tunnel failed
    #[error(display = "Tunnel failed")]
    TunnelError(#[error(source)] TunnelError),

    /// Failed to create tunnel obfuscator
    #[error(display = "Failed to create tunnel obfuscator")]
    CreateObfuscatorError(#[error(source)] ObfuscationError),

    /// Failed to run tunnel obfuscator
    #[error(display = "Tunnel obfuscator failed")]
    ObfuscatorError(#[error(source)] ObfuscationError),

    /// Failed to set up connectivity monitor
    #[error(display = "Connectivity monitor failed")]
    ConnectivityMonitorError(#[error(source)] connectivity_check::Error),

    /// Failed to set up IP interfaces.
    #[cfg(windows)]
    #[error(display = "Failed to set up IP interfaces")]
    IpInterfacesError,

    /// Failed to set IP addresses on WireGuard interface
    #[cfg(target_os = "windows")]
    #[error(display = "Failed to set IP addresses on WireGuard interface")]
    SetIpAddressesError,
}

/// Spawns and monitors a wireguard tunnel
pub struct WireguardMonitor {
    runtime: tokio::runtime::Handle,
    /// Tunnel implementation
    tunnel: Arc<Mutex<Option<Box<dyn Tunnel>>>>,
    /// Callback to signal tunnel events
    event_callback: Box<
        dyn (Fn(TunnelEvent) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>)
            + Send
            + Sync
            + 'static,
    >,
    close_msg_sender: sync_mpsc::Sender<CloseMsg>,
    close_msg_receiver: sync_mpsc::Receiver<CloseMsg>,
    pinger_stop_sender: sync_mpsc::Sender<()>,
    _obfuscator: Option<ObfuscatorHandle>,
}

/// Simple wrapper that automatically cancels the future which runs an obfuscator.
struct ObfuscatorHandle {
    abort_handle: FutureAbortHandle,
}

impl ObfuscatorHandle {
    pub fn new(abort_handle: FutureAbortHandle) -> Self {
        Self { abort_handle }
    }
}

impl Drop for ObfuscatorHandle {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

#[cfg(target_os = "linux")]
lazy_static! {
    /// Overrides the preference for the kernel module for WireGuard.
    static ref FORCE_USERSPACE_WIREGUARD: bool = env::var("TALPID_FORCE_USERSPACE_WIREGUARD")
        .map(|v| v != "0")
        .unwrap_or(false);

    static ref FORCE_NM_WIREGUARD: bool = env::var("TALPID_FORCE_NM_WIREGUARD")
        .map(|v| v != "0")
        .unwrap_or(false);
}

fn maybe_create_obfuscator(
    runtime: &tokio::runtime::Handle,
    config: &mut Config,
    close_msg_sender: sync_mpsc::Sender<CloseMsg>,
) -> Result<Option<ObfuscatorHandle>> {
    // There are one or two peers.
    // The first one is always the entry relay.
    let mut first_peer = config.peers.get_mut(0).expect("missing peer");

    if let Some(ref obfuscator_config) = config.obfuscator_config {
        match obfuscator_config {
            ObfuscatorConfig::Udp2Tcp{endpoint} => {
                log::trace!("Connecting to Udp2Tcp endpoint {:?}", *endpoint);
                let settings = Udp2TcpSettings {
                    peer: *endpoint,
                    #[cfg(target_os = "linux")]
                    fwmark: Some(crate::linux::TUNNEL_FW_MARK),
                };
                let obfuscator = runtime
                    .block_on(create_obfuscator(&ObfuscationSettings::Udp2Tcp(settings)))
                    .map_err(Error::CreateObfuscatorError)?;
                let endpoint = obfuscator.endpoint();
                log::trace!("Patching first WireGuard peer to become {:?}", endpoint);
                first_peer.endpoint = endpoint.address;
                let (runner, abort_handle) = abortable(async move {
                    match obfuscator.run().await {
                        Ok(_) => {
                            let _ = close_msg_sender.send(CloseMsg::ObfuscatorExpired);
                        }
                        Err(error) => {
                            log::error!(
                                "{}",
                                error.display_chain_with_msg("Obfuscation controller failed")
                            );
                            let _ = close_msg_sender
                                .send(CloseMsg::ObfuscatorFailed(Error::ObfuscatorError(error)));
                        }
                    }
                });
                runtime.spawn(runner);
                return Ok(Some(ObfuscatorHandle::new(abort_handle)));
            },
            _ => {
                unreachable!("TODO: Handle all obfuscators");
            },
        }
    }
    Ok(None)
}

impl WireguardMonitor {
    /// Starts a WireGuard tunnel with the given config
    pub fn start<
        F: (Fn(TunnelEvent) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>)
            + Send
            + Sync
            + Clone
            + 'static,
    >(
        runtime: tokio::runtime::Handle,
        mut config: Config,
        log_path: Option<&Path>,
        resource_dir: &Path,
        on_event: F,
        tun_provider: Arc<Mutex<TunProvider>>,
        route_manager: RouteManagerHandle,
        retry_attempt: u32,
        tunnel_close_rx: oneshot::Receiver<()>,
    ) -> Result<WireguardMonitor> {
        let endpoint_addrs: Vec<IpAddr> =
            config.peers.iter().map(|peer| peer.endpoint.ip()).collect();
        let (close_msg_sender, close_msg_receiver) = sync_mpsc::channel();

        let obfuscator = maybe_create_obfuscator(&runtime, &mut config, close_msg_sender.clone())?;

        #[cfg(target_os = "windows")]
        let (setup_done_tx, mut setup_done_rx) = mpsc::channel(0);
        let tunnel = Self::open_tunnel(
            runtime.clone(),
            &config,
            log_path,
            resource_dir,
            tun_provider,
            #[cfg(target_os = "windows")]
            setup_done_tx,
        )?;
        let iface_name = tunnel.get_interface_name().to_string();

        let event_callback = Box::new(on_event.clone());
        let (pinger_tx, pinger_rx) = sync_mpsc::channel();
        let monitor = WireguardMonitor {
            runtime: runtime.clone(),
            tunnel: Arc::new(Mutex::new(Some(tunnel))),
            event_callback,
            close_msg_sender,
            close_msg_receiver,
            pinger_stop_sender: pinger_tx,
            _obfuscator: obfuscator,
        };

        let gateway = config.ipv4_gateway;
        let close_sender = monitor.close_msg_sender.clone();
        let mut connectivity_monitor = connectivity_check::ConnectivityMonitor::new(
            gateway,
            #[cfg(not(target_os = "windows"))]
            iface_name.clone(),
            Arc::downgrade(&monitor.tunnel),
            pinger_rx,
        )
        .map_err(Error::ConnectivityMonitorError)?;

        let metadata = Self::tunnel_metadata(&iface_name, &config);

        tokio::spawn(async move {
            #[cfg(windows)]
            {
                let iface_close_sender = close_sender.clone();
                let result = match setup_done_rx.next().await {
                    Some(result) => result.map_err(|error| {
                        log::error!(
                            "{}",
                            error.display_chain_with_msg("Failed to configure tunnel interface")
                        );
                        iface_close_sender
                            .send(CloseMsg::SetupError(Error::IpInterfacesError))
                            .unwrap_or(())
                    }),
                    None => Err(()),
                };
                if result.is_err() {
                    return;
                }
            }

            (on_event)(TunnelEvent::InterfaceUp(metadata.clone())).await;

            let setup_iface_routes = async move {
                #[cfg(target_os = "windows")]
                if !crate::winnet::add_device_ip_addresses(&iface_name, &config.tunnel.addresses) {
                    return Err(Error::SetIpAddressesError);
                }

                #[cfg(target_os = "linux")]
                route_manager
                    .create_routing_rules(config.enable_ipv6)
                    .await
                    .map_err(Error::SetupRoutingError)?;

                let routes = Self::get_in_tunnel_routes(&iface_name, &config)
                    .chain(Self::get_tunnel_traffic_routes(&endpoint_addrs));

                route_manager
                    .add_routes(routes.collect())
                    .await
                    .map_err(Error::SetupRoutingError)
            };

            if let Err(error) = setup_iface_routes.await {
                let _ = close_sender.send(CloseMsg::SetupError(error));
                return;
            }

            tokio::task::spawn_blocking(move || {
                match connectivity_monitor.establish_connectivity(retry_attempt) {
                    Ok(true) => {
                        tokio::spawn((on_event)(TunnelEvent::Up(metadata)));

                        if let Err(error) = connectivity_monitor.run() {
                            log::error!(
                                "{}",
                                error.display_chain_with_msg("Connectivity monitor failed")
                            );
                        }
                    }
                    Ok(false) => log::warn!("Timeout while checking tunnel connection"),
                    Err(error) => {
                        log::error!(
                            "{}",
                            error.display_chain_with_msg("Failed to check tunnel connection")
                        );
                    }
                }
            })
            .await
            .expect("connectivity monitor thread panicked");

            let _ = close_sender.send(CloseMsg::PingErr);
        });

        let mut close_handle = monitor.close_handle();
        tokio::spawn(async move {
            if tunnel_close_rx.await.is_ok() {
                close_handle.close();
            }
        });

        Ok(monitor)
    }

    #[allow(unused_variables)]
    fn open_tunnel(
        runtime: tokio::runtime::Handle,
        config: &Config,
        log_path: Option<&Path>,
        resource_dir: &Path,
        tun_provider: Arc<Mutex<TunProvider>>,
        #[cfg(windows)] setup_done_tx: mpsc::Sender<std::result::Result<(), BoxedError>>,
    ) -> Result<Box<dyn Tunnel>> {
        #[cfg(target_os = "linux")]
        if !*FORCE_USERSPACE_WIREGUARD {
            if crate::dns::will_use_nm() {
                match wireguard_kernel::NetworkManagerTunnel::new(runtime, config) {
                    Ok(tunnel) => {
                        log::debug!("Using NetworkManager to use kernel WireGuard implementation");
                        return Ok(Box::new(tunnel));
                    }
                    Err(err) => {
                        log::error!(
                            "{}",
                            err.display_chain_with_msg(
                                "Failed to initialize WireGuard tunnel via NetworkManager"
                            )
                        );
                    }
                };
            } else {
                match wireguard_kernel::NetlinkTunnel::new(runtime, config) {
                    Ok(tunnel) => {
                        log::debug!("Using kernel WireGuard implementation");
                        return Ok(Box::new(tunnel));
                    }
                    Err(error) => {
                        log::error!(
                            "{}",
                            error.display_chain_with_msg(
                                "Failed to setup kernel WireGuard device, falling back to the userspace implementation"
                            )
                        );
                    }
                };
            }
        }

        #[cfg(target_os = "windows")]
        if config.use_wireguard_nt {
            match wireguard_nt::WgNtTunnel::start_tunnel(
                config,
                log_path,
                resource_dir,
                setup_done_tx.clone(),
            ) {
                Ok(tunnel) => {
                    log::debug!("Using WireGuardNT");
                    return Ok(Box::new(tunnel));
                }
                Err(error) => {
                    log::error!(
                        "{}",
                        error.display_chain_with_msg("Failed to setup WireGuardNT tunnel")
                    );
                }
            }
        }

        #[cfg(any(target_os = "linux", windows))]
        log::debug!("Using userspace WireGuard implementation");
        Ok(Box::new(
            WgGoTunnel::start_tunnel(
                &config,
                log_path,
                #[cfg(not(windows))]
                tun_provider,
                #[cfg(not(windows))]
                Self::get_tunnel_destinations(config),
                #[cfg(windows)]
                setup_done_tx,
            )
            .map_err(Error::TunnelError)?,
        ))
    }

    /// Returns a close handle for the tunnel
    fn close_handle(&self) -> CloseHandle {
        CloseHandle {
            chan: self.close_msg_sender.clone(),
        }
    }

    /// Blocks the current thread until tunnel disconnects
    pub fn wait(mut self) -> Result<()> {
        let wait_result = match self.close_msg_receiver.recv() {
            Ok(CloseMsg::PingErr) => Err(Error::TimeoutError),
            Ok(CloseMsg::Stop) | Ok(CloseMsg::ObfuscatorExpired) => Ok(()),
            Ok(CloseMsg::SetupError(error)) => Err(error),
            Ok(CloseMsg::ObfuscatorFailed(error)) => Err(error),
            Err(_) => Ok(()),
        };

        let _ = self.pinger_stop_sender.send(());

        self.stop_tunnel();

        self.runtime
            .block_on((self.event_callback)(TunnelEvent::Down));
        wait_result
    }

    fn stop_tunnel(&mut self) {
        match self.tunnel.lock().expect("Tunnel lock poisoned").take() {
            Some(tunnel) => {
                if let Err(e) = tunnel.stop() {
                    log::error!("{}", e.display_chain_with_msg("Failed to stop tunnel"));
                }
            }
            None => {
                log::debug!("Tunnel already stopped");
            }
        }
    }

    fn get_tunnel_destinations(config: &Config) -> impl Iterator<Item = ipnetwork::IpNetwork> + '_ {
        let routes = config
            .peers
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter())
            .cloned();
        #[cfg(target_os = "linux")]
        {
            routes
        }
        #[cfg(not(target_os = "linux"))]
        {
            routes.flat_map(|allowed_ip| {
                if allowed_ip.prefix() == 0 {
                    if allowed_ip.is_ipv4() {
                        vec!["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()]
                    } else {
                        vec!["8000::/1".parse().unwrap(), "::/1".parse().unwrap()]
                    }
                } else {
                    vec![allowed_ip]
                }
            })
        }
    }

    #[cfg(target_os = "windows")]
    fn get_in_tunnel_routes<'a>(
        iface_name: &str,
        config: &'a Config,
    ) -> impl Iterator<Item = RequiredRoute> + 'a {
        let node_v4 =
            routing::Node::new(config.ipv4_gateway.clone().into(), iface_name.to_string());
        let node_v6 = if let Some(ipv6_gateway) = config.ipv6_gateway.as_ref() {
            routing::Node::new(ipv6_gateway.clone().into(), iface_name.to_string())
        } else {
            routing::Node::device(iface_name.to_string())
        };
        Self::get_tunnel_destinations(config).map(move |network| {
            if network.is_ipv4() {
                RequiredRoute::new(network, node_v4.clone())
            } else {
                RequiredRoute::new(network, node_v6.clone())
            }
        })
    }

    /// On linux, there is no need
    #[cfg(target_os = "linux")]
    fn get_tunnel_traffic_routes<'a>(
        _endpoints: &'a [IpAddr],
    ) -> impl Iterator<Item = RequiredRoute> {
        std::iter::empty()
    }

    #[cfg(not(target_os = "linux"))]
    fn get_tunnel_traffic_routes<'a>(
        endpoints: &'a [IpAddr],
    ) -> impl Iterator<Item = RequiredRoute> + 'a {
        endpoints.iter().map(|ip| {
            RequiredRoute::new(
                ipnetwork::IpNetwork::from(*ip),
                routing::NetNode::DefaultNode,
            )
        })
    }

    #[cfg(target_os = "linux")]
    fn get_in_tunnel_routes<'a>(
        iface_name: &str,
        config: &'a Config,
    ) -> impl Iterator<Item = RequiredRoute> + 'a {
        use netlink_packet_route::rtnl::constants::RT_TABLE_MAIN;

        let node = routing::Node::device(iface_name.to_string());
        let v4_node = node.clone();
        let v6_node = node.clone();
        Self::get_tunnel_destinations(config)
            .map(move |network| {
                if network.prefix() == 0 {
                    RequiredRoute::new(network, node.clone())
                } else {
                    RequiredRoute::new(network, node.clone()).table(u32::from(RT_TABLE_MAIN))
                }
            })
            .chain(std::iter::once(
                RequiredRoute::new(
                    ipnetwork::Ipv4Network::from(config.ipv4_gateway).into(),
                    v4_node,
                )
                .table(u32::from(RT_TABLE_MAIN)),
            ))
            .chain(config.ipv6_gateway.map(|gateway| {
                RequiredRoute::new(ipnetwork::Ipv6Network::from(gateway).into(), v6_node)
                    .table(u32::from(RT_TABLE_MAIN))
            }))
    }

    #[cfg(all(not(target_os = "linux"), not(windows)))]
    fn get_in_tunnel_routes<'a>(
        iface_name: &str,
        config: &'a Config,
    ) -> impl Iterator<Item = RequiredRoute> + 'a {
        let node = routing::Node::device(iface_name.to_string());
        Self::get_tunnel_destinations(config)
            .map(move |network| RequiredRoute::new(network, node.clone()))
    }

    fn tunnel_metadata(interface_name: &str, config: &Config) -> TunnelMetadata {
        TunnelMetadata {
            interface: interface_name.to_string(),
            ips: config.tunnel.addresses.clone(),
            ipv4_gateway: config.ipv4_gateway,
            ipv6_gateway: config.ipv6_gateway,
        }
    }
}

enum CloseMsg {
    Stop,
    PingErr,
    SetupError(Error),
    ObfuscatorExpired,
    ObfuscatorFailed(Error),
}

/// Close handle for a WireGuard tunnel.
#[derive(Clone, Debug)]
pub struct CloseHandle {
    chan: sync_mpsc::Sender<CloseMsg>,
}

impl CloseHandle {
    /// Closes a WireGuard tunnel
    pub fn close(&mut self) {
        if let Err(e) = self.chan.send(CloseMsg::Stop) {
            log::trace!("Failed to send close message to wireguard tunnel: {}", e);
        }
    }
}

pub(crate) trait Tunnel: Send {
    fn get_interface_name(&self) -> String;
    fn stop(self: Box<Self>) -> std::result::Result<(), TunnelError>;
    fn get_tunnel_stats(&self) -> std::result::Result<stats::StatsMap, TunnelError>;
}

/// Errors to be returned from WireGuard implementations, namely implementers of the Tunnel trait
#[derive(err_derive::Error, Debug)]
#[error(no_from)]
pub enum TunnelError {
    /// A recoverable error occurred while starting the wireguard tunnel
    ///
    /// This is an error returned by wireguard-go that indicates that trying to establish the
    /// tunnel again should work normally. The error encountered is known to be sporadic.
    #[error(display = "Recoverable error while starting wireguard tunnel")]
    RecoverableStartWireguardError,

    /// An unrecoverable error occurred while starting the wireguard tunnel
    ///
    /// This is an error returned by wireguard-go that indicates that trying to establish the
    /// tunnel again will likely fail with the same error. An error was encountered during tunnel
    /// configuration which can't be dealt with gracefully.
    #[error(display = "Failed to start wireguard tunnel")]
    FatalStartWireguardError,

    /// Failed to tear down wireguard tunnel.
    #[error(display = "Failed to stop wireguard tunnel. Status: {}", status)]
    StopWireguardError {
        /// Returned error code
        status: i32,
    },

    /// Error whilst trying to parse the WireGuard config to read the stats
    #[error(display = "Reading tunnel stats failed")]
    StatsError(#[error(source)] stats::Error),

    /// Error whilst trying to retrieve config of a WireGuard tunnel
    #[error(display = "Failed to get config of WireGuard tunnel")]
    GetConfigError,

    /// Failed to duplicate tunnel file descriptor for wireguard-go
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
    #[error(display = "Failed to duplicate tunnel file descriptor for wireguard-go")]
    FdDuplicationError(#[error(source)] nix::Error),

    /// Failed to setup a tunnel device.
    #[cfg(not(windows))]
    #[error(display = "Failed to create tunnel device")]
    SetupTunnelDeviceError(#[error(source)] tun_provider::Error),

    /// Failed to setup a tunnel device.
    #[cfg(windows)]
    #[error(display = "Failed to config IP interfaces on tunnel device")]
    SetupIpInterfaces(#[error(source)] io::Error),

    /// Failed to configure Wireguard sockets to bypass the tunnel.
    #[cfg(target_os = "android")]
    #[error(display = "Failed to configure Wireguard sockets to bypass the tunnel")]
    BypassError(#[error(source)] tun_provider::Error),

    /// Invalid tunnel interface name.
    #[error(display = "Invalid tunnel interface name")]
    InterfaceNameError(#[error(source)] std::ffi::NulError),

    /// Failed to convert adapter alias to UTF-8.
    #[cfg(target_os = "windows")]
    #[error(display = "Failed to convert adapter alias")]
    InvalidAlias,

    /// Failure to set up logging
    #[error(display = "Failed to set up logging")]
    LoggingError(#[error(source)] logging::Error),
}
