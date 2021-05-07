package net.mullvad.mullvadvpn.viewmodel

import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.shareIn
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.R
import net.mullvad.mullvadvpn.applist.AppData
import net.mullvad.mullvadvpn.applist.ApplicationsProvider
import net.mullvad.mullvadvpn.applist.ViewIntent
import net.mullvad.mullvadvpn.model.ListItemData
import net.mullvad.mullvadvpn.model.WidgetState
import net.mullvad.mullvadvpn.ui.serviceconnection.SplitTunneling

class SplitTunnelingViewModel(
    private val appsProvider: ApplicationsProvider,
    private val splitTunneling: SplitTunneling,
    dispatcher: CoroutineDispatcher
) : ViewModel() {
    private val listItemsSink = MutableSharedFlow<List<ListItemData>>(replay = 1)
    // read-only public view
    val listItems: SharedFlow<List<ListItemData>> = listItemsSink.asSharedFlow()

    private val intentFlow = MutableSharedFlow<ViewIntent>()
    private val isUIReady = CompletableDeferred<Unit>()
    private val excludedApps: MutableMap<String, AppData> = mutableMapOf()
    private val notExcludedApps: MutableMap<String, AppData> = mutableMapOf()

    private val defaultListItems: List<ListItemData> = listOf(
        createTextItem(R.string.split_tunneling_description),
        createDivider(0),
        createSearchItem(R.string.search_hint)
    )
    private var isSystemAppsVisible = false

    init {
        viewModelScope.launch(dispatcher) {
            listItemsSink.emit(defaultListItems + createDivider(1) + createProgressItem())
            // this will be removed after changes on native to ignore enable parameter
            if (!splitTunneling.enabled)
                splitTunneling.enabled = true
            fetchData()
        }
        viewModelScope.launch(dispatcher) {
            intentFlow.shareIn(viewModelScope, SharingStarted.WhileSubscribed())
                .collect(::handleIntents)
        }
    }

    suspend fun processIntent(intent: ViewIntent) = intentFlow.emit(intent)

    override fun onCleared() {
        splitTunneling.persist()
        super.onCleared()
    }

    private suspend fun handleIntents(viewIntent: ViewIntent) {
        when (viewIntent) {
            is ViewIntent.ChangeApplicationGroup -> {
                viewIntent.item.action?.let {
                    if (excludedApps.containsKey(it.identifier)) {
                        removeFromExcluded(it.identifier)
                    } else {
                        addToExcluded(it.identifier)
                    }
                    publishList()
                }
            }
            is ViewIntent.ViewIsReady -> isUIReady.complete(Unit)
            is ViewIntent.ShowSystemApps -> {
                isSystemAppsVisible = viewIntent.show
                publishList()
            }
            is ViewIntent.SearchApplication -> {
                if (isUIReady.isCompleted)
                    publishList(viewIntent.term)
            }
            // else -> Log.e("mullvad", "Unhandled ViewIntent: $viewIntent")
        }
    }

    private fun removeFromExcluded(packageName: String) {
        excludedApps.remove(packageName)?.let { appInfo ->
            notExcludedApps[packageName] = appInfo
            splitTunneling.includeApp(packageName)
        }
    }

    private fun addToExcluded(packageName: String) {
        notExcludedApps.remove(packageName)?.let { appInfo ->
            excludedApps[packageName] = appInfo
            splitTunneling.excludeApp(packageName)
        }
    }

    private suspend fun fetchData() {
        appsProvider.getAppsList()
            .partition { app -> splitTunneling.isAppExcluded(app.packageName) }
            .let { (excludedAppsList, notExcludedAppsList) ->
                // TODO: remove potential package names from splitTunneling list
                //       if they already uninstalled or filtered; but not in ViewModel
                excludedAppsList.map { it.packageName to it }.toMap(excludedApps)
                notExcludedAppsList.map { it.packageName to it }.toMap(notExcludedApps)
            }
        isUIReady.await()
        publishList()
    }

    private suspend fun publishList(searchItem: String? = null) {
        val listItems = ArrayList(
            if (searchItem != null) {
                emptyList()
            } else {
                defaultListItems
            }
        )
        if (excludedApps.isNotEmpty()) {
            excludedApps.values.sortedBy { it.name }
                .filter { appData ->
                    if (searchItem != null) {
                        appData.name.contains(searchItem, ignoreCase = true)
                    } else {
                        true
                    }
                }.map { info ->
                    createApplicationItem(info, true)
                }.takeIf { it.isNotEmpty() }?.run {
                    listItems += createDivider(1)
                    listItems += createMainItem(R.string.exclude_applications)
                    listItems += this
                }
        }
//<<<<<<< HEAD
//<<<<<<< HEAD
        val shownNotExcludedApps =
            notExcludedApps.filter { app -> !app.value.isSystemApp || isSystemAppsVisible }
//        if (shownNotExcludedApps.isNotEmpty()) {
//            listItems += createDivider(1)
//            listItems += createSwitchItem(R.string.show_system_apps, isSystemAppsVisible)
//=======
//        if (notExcludedApps.isNotEmpty()) {
//            listItems += createDivider(2)
//>>>>>>> 11fa3acb7 (Init filter view)


//            listItems += createMainItem(R.string.all_applications)
//            listItems += shownNotExcludedApps.values.sortedBy { it.name }
//                .take(
//                    if (searchItem) {
//                        notExcludedApps.values.size



//=======
        if (shownNotExcludedApps.isNotEmpty()) {
            shownNotExcludedApps.values.sortedBy { it.name }
                .filter { appData ->
                    if (searchItem != null) {
                        appData.name.contains(searchItem, ignoreCase = true)
                    } else {
                        true
                    }
                }.map { info ->
                    createApplicationItem(info, false)
                }.takeIf { it.isNotEmpty() }?.run {
                    listItems += createDivider(2)
                    listItems += createMainItem(R.string.all_applications)
                    listItems += this
                }
        }
        if (searchItem != null && listItems.isEmpty()) {
            listItems.add(
                ListItemData.build("text_no_search_results") {
                    type = ListItemData.PLAIN
                    text = "No results for $searchItem. \n" +
                        "Try a different search."
                    action = ListItemData.ItemAction(text.toString())
                }
            )
        }
        listItemsSink.emit(listItems)
    }

    private fun createApplicationItem(appData: AppData, checked: Boolean): ListItemData =
        ListItemData.build(appData.packageName) {
            type = ListItemData.APPLICATION
            text = appData.name
            iconRes = appData.iconRes
            action = ListItemData.ItemAction(appData.packageName)
            widget = WidgetState.ImageState(
                if (checked) R.drawable.ic_icons_remove else R.drawable.ic_icons_add
            )
        }

    private fun createDivider(id: Int): ListItemData = ListItemData.build("space_$id") {
        type = ListItemData.DIVIDER
    }

    private fun createMainItem(@StringRes text: Int): ListItemData =
        ListItemData.build("header_$text") {
            type = ListItemData.ACTION
            textRes = text
        }

    private fun createTextItem(@StringRes text: Int): ListItemData =
        ListItemData.build("text_$text") {
            type = ListItemData.PLAIN
            textRes = text
            action = ListItemData.ItemAction(text.toString())
        }

    private fun createSearchItem(@StringRes text: Int): ListItemData =
        ListItemData.build("search_$text") {
            type = ListItemData.SEARCH_VIEW
            textRes = text
            action = ListItemData.ItemAction(text.toString())
        }

    private fun createProgressItem(): ListItemData = ListItemData.build(identifier = "progress") {
        type = ListItemData.PROGRESS
    }

    private fun createSwitchItem(@StringRes text: Int, checked: Boolean): ListItemData =
        ListItemData.build(identifier = "switch_$text") {
            type = ListItemData.ACTION
            textRes = text
            action = ListItemData.ItemAction(text.toString())
            widget = WidgetState.SwitchState(checked)
        }
}
