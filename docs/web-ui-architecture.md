# Technitium DNS Server — Web UI Architecture

## Overview

Technitium DNS Server exposes two separate web frontends, both served by the same embedded HTTP server (`DnsServerCore.HttpApi`):

| Frontend | Path | Purpose |
|---|---|---|
| **Admin Console** | `DnsServerCore/www/` | Full management SPA for authenticated administrators |
| **DoH Info Page** | `DnsServerCore/dohwww/` | Public informational page for DNS-over-HTTPS users |

Both are static file trees (HTML + CSS + JS). There is no build step, bundler, or framework — everything is plain HTML5, vanilla JavaScript, and jQuery.

---

## 1. Admin Console (`www/`)

### 1.1 File Inventory

```
www/
├── index.html              ← Single HTML file; all UI lives here
├── css/
│   ├── bootstrap.min.css   ← Bootstrap 3 grid/components
│   ├── font-awesome.min.css← Icons
│   └── main.css            ← Custom application styles + dark mode
├── img/
│   ├── logo25x25.png       ← Header logo
│   ├── loader.gif          ← AJAX loading spinner
│   └── loader-small.gif    ← Inline loading spinner
├── json/
│   ├── dnsclient-server-list-builtin.json  ← Built-in DNS server presets
│   └── dnsclient-server-list-custom.json   ← Optional user-defined presets
└── js/
    ├── jquery.min.js       ← jQuery (DOM, AJAX)
    ├── bootstrap.min.js    ← Bootstrap 3 JS (modals, tabs, dropdowns)
    ├── Chart.min.js        ← Chart.js (dashboard charts)
    ├── moment.min.js       ← Moment.js (date/time formatting)
    ├── common.js           ← Shared utilities
    ├── auth.js             ← Authentication & user management
    ├── main.js             ← App bootstrap, routing, settings, dashboard
    ├── zone.js             ← DNS zone & record management
    ├── other-zones.js      ← Cache, Allowed, Blocked zones
    ├── apps.js             ← DNS application (plugin) management
    ├── dnsclient.js        ← Interactive DNS query tool
    ├── dhcp.js             ← DHCP leases & scopes
    ├── logs.js             ← Log viewer & query logs
    └── cluster.js          ← Multi-node cluster management
```

### 1.2 Script Loading Order

`index.html` loads scripts in this fixed order, establishing the dependency chain:

```
jquery.min.js
  └─ bootstrap.min.js
  └─ Chart.min.js
  └─ moment.min.js
  └─ common.js          ← must load before any module that calls HTTPRequest/showAlert
       └─ main.js       ← defines showPageLogin/showPageMain; loaded first of app scripts
       └─ auth.js       ← reads/writes sessionData; calls showPageMain/showPageLogin
       └─ cluster.js    ← calls updateAllClusterNodeDropDowns (used by main.js)
       └─ zone.js       ← calls showPageLogin on invalid token
       └─ other-zones.js
       └─ apps.js
       └─ dnsclient.js
       └─ dhcp.js
       └─ logs.js
```

---

## 2. SPA Navigation Model

The application is a **zero-router SPA**: there is a single URL (`/`) and navigation is achieved entirely by toggling CSS `display` on pre-rendered `<div>` elements. There is no hash routing, no History API, and no dynamic HTML loading.

### 2.1 Page-Level Containers

```
<body>
 ├─ #header              ← Logo + user dropdown menu (populated by main.js at init)
 ├─ #content
 │   ├─ .AlertPlaceholder  ← Global alert banner slot
 │   ├─ #pageLogin          ← Login form (visible when logged out)
 │   └─ #pageMain           ← Main panel (visible when logged in)
 │       └─ .panel
 │           ├─ .panel-heading  ← "DNS Server — <domain>" + update link
 │           └─ .panel-body
 │               └─ Bootstrap tab set (ul.nav-tabs + div.tab-content)
 └─ (modals scattered at document root)
```

### 2.2 Main Tab Panels

Each tab maps to a feature module:

```
ul.nav-tabs
 ├─ #mainPanelTabListDashboard      → #mainPanelTabPaneDashboard   [main.js]
 ├─ #mainPanelTabListZones          → #mainPanelTabPaneZones        [zone.js]
 ├─ #mainPanelTabListCachedZones    → #mainPanelTabPaneCachedZones  [other-zones.js]
 ├─ #mainPanelTabListAllowedZones   → #mainPanelTabPaneAllowedZones [other-zones.js]
 ├─ #mainPanelTabListBlockedZones   → #mainPanelTabPaneBlockedZones [other-zones.js]
 ├─ #mainPanelTabListApps           → #mainPanelTabPaneApps         [apps.js]
 ├─ #mainPanelTabListDnsClient      → #mainPanelTabPaneDnsClient    [dnsclient.js]
 ├─ #mainPanelTabListSettings       → #mainPanelTabPaneSettings      [main.js]
 ├─ #mainPanelTabListDhcp           → #mainPanelTabPaneDhcp         [dhcp.js]
 ├─ #mainPanelTabListAdmin          → #mainPanelTabPaneAdmin         [auth.js]
 ├─ #mainPanelTabListLogs           → #mainPanelTabPaneLogs         [logs.js]
 └─ #mainPanelTabListAbout          → #mainPanelTabPaneAbout         [main.js]
```

Tab visibility is controlled at login time based on `sessionData.info.permissions.*`.

---

## 3. JavaScript Module Responsibilities

### 3.1 Module Dependency Diagram

```
                        ┌─────────────┐
                        │  common.js  │
                        │  ─────────  │
                        │ HTTPRequest │
                        │ showAlert   │
                        │ hideAlert   │
                        │ htmlEncode  │
                        │ sortTable   │
                        │ serializeT… │
                        │ cleanTextL… │
                        └──────┬──────┘
                               │  used by all modules below
          ┌─────────────┬──────┴───────┬──────────────┬───────────────┐
          │             │              │               │               │
     ┌────▼────┐  ┌─────▼────┐  ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
     │ auth.js │  │  main.js │  │  zone.js  │  │other-zones│  │  apps.js  │
     └─────────┘  └──────────┘  └───────────┘  └───────────┘  └───────────┘
          │             │
          │       ┌─────┴──────────────┬────────────────┬────────────┐
          │       │                    │                │            │
     ┌────▼────┐  │             ┌──────▼──┐  ┌─────────▼──┐  ┌──────▼───┐
     │cluster.j│  │             │ dhcp.js │  │dnsclient.js│  │  logs.js │
     └─────────┘  │             └─────────┘  └────────────┘  └──────────┘
                  │
            ┌─────▼──────────────────┐
            │  Chart.js / moment.js  │
            │  (dashboard rendering) │
            └────────────────────────┘
```

### 3.2 Module Descriptions

| Module | Key Functions | API Namespaces |
|---|---|---|
| **common.js** | `HTTPRequest()`, `showAlert()`, `hideAlert()`, `htmlEncode()`, `htmlDecode()`, `sortTable()`, `serializeTableData()`, `cleanTextList()` | — |
| **auth.js** | `login()`, `logout()`, session restore on load, `showChangePasswordModal()`, `showConfigure2FAModal()`, `enable2FA()`, `disable2FA()`, `showMyProfileModal()`, user CRUD, group CRUD, permission management | `api/user/*`, `api/admin/users/*`, `api/admin/groups/*`, `api/admin/permissions/*`, `api/admin/sessions/*` |
| **main.js** | `showPageLogin()`, `showPageMain()`, `refreshDnsSettings()`, `saveDnsSettings()`, `refreshDashboard()`, `showTopStats()`, `checkForUpdate()`, `loadQuickBlockLists()`, `toggleTheme()`, `backupSettings()`, `restoreSettings()`, settings form event wiring | `api/settings/*`, `api/dashboard/*`, `api/user/checkForUpdate` |
| **zone.js** | `refreshZones()`, `addZone()`, `deleteZone()`, `enableZone()`, `disableZone()`, zone options, `editZone()` (sub-view), `addRecord()`, `editRecord()`, `deleteRecord()`, DNSSEC sign/unsign/properties, TSIG key management, zone import/export | `api/zones/*` |
| **other-zones.js** | `refreshCachedZonesList()`, `deleteCachedZone()`, `flushDnsCache()`, `refreshAllowedZonesList()`, `allowZone()`, `deleteAllowedZone()`, `importAllowedZones()`, `refreshBlockedZonesList()`, `blockZone()`, `deleteBlockedZone()`, `importBlockedZones()` | `api/cache/*`, `api/allowed/*`, `api/blocked/*` |
| **apps.js** | `refreshApps()`, `installApp()`, `updateApp()`, `uninstallApp()`, `showStoreAppsModal()`, `installStoreApp()`, `updateStoreApp()`, `showAppConfigModal()`, `saveAppConfig()` | `api/apps/*` |
| **dnsclient.js** | `resolveQuery()`, `queryDnsServer()`, `loadServerList()` (reads JSON presets), dropdown list interaction | `api/dnsClient/resolve` |
| **dhcp.js** | `refreshDhcpTab()`, `refreshDhcpLeases()`, `convertToReservedLease()`, `convertToDynamicLease()`, `refreshDhcpScopes()`, `editDhcpScope()`, `saveDhcpScope()`, `deleteDhcpScope()` | `api/dhcp/*` |
| **logs.js** | `refreshLogsTab()`, `refreshLogFilesList()`, log file viewer (download/delete), `refreshQueryLogsTab()`, `queryLogs()` | `api/logs/*` |
| **cluster.js** | `refreshAdminCluster()`, `updateSelfClusterNode()`, `updatePrimaryClusterNode()`, `removeSecondaryClusterNode()`, `promoteToPrimaryClusterNode()`, `initializeNewCluster()`, `initializeJoinCluster()`, `updateAllClusterNodeDropDowns()` | `api/admin/cluster/*` |

---

## 4. Authentication & Session Flow

```
Browser loads /
       │
       ▼
auth.js: $(function(){...})
       │
       ├─ localStorage has "token"?
       │       YES → GET api/user/session/get?token=...
       │               ├─ 200 ok  → sessionData = response
       │               │            showPageMain()
       │               └─ error   → showPageLogin()
       │
       └─ NO → showPageLogin()
               └─ auto-attempt login("admin","admin")
                       ├─ success → sessionData set
                       │           localStorage.setItem("token", ...)
                       │           showPageMain()
                       ├─ error   → hideAlert() (silent fail, user must log in)
                       └─ 2fa-required → show OTP input
```

**Token lifecycle:**
- Stored in `localStorage["token"]`
- Appended to every API call as `?token=<value>`
- On `invalid-token` response: `window.location = "/"` (full page reload → login screen)
- On logout: `api/user/logout` called, token removed, `showPageLogin()` called

**Global session state:**
```javascript
var sessionData = {
    token: "...",
    username: "...",
    displayName: "...",
    totpEnabled: false,
    info: {
        version: "...",
        dnsServerDomain: "...",
        uptimestamp: "...",
        useSoaSerialDateScheme: false,
        dnssecValidation: true,
        permissions: {
            Dashboard:      { canView, canModify, canDelete },
            Zones:          { canView, canModify, canDelete },
            Cache:          { canView, canModify, canDelete },
            Allowed:        { canView, canModify, canDelete },
            Blocked:        { canView, canModify, canDelete },
            Apps:           { canView, canModify, canDelete },
            DnsClient:      { canView, canModify, canDelete },
            Settings:       { canView, canModify, canDelete },
            DhcpServer:     { canView, canModify, canDelete },
            Administration: { canView, canModify, canDelete },
            Logs:           { canView, canModify, canDelete }
        }
    }
}
```

---

## 5. HTTP Communication Layer

All API calls go through the single `HTTPRequest()` function defined in `common.js`. It wraps `$.ajax()` and normalises the server response envelope.

### 5.1 Request Pattern

```
GET  api/<domain>/<action>?token=<token>&param1=value1...
POST api/<domain>/<action>?token=<token>
     body: param1=value1&param2=value2   (application/x-www-form-urlencoded)
           OR FormData                   (for file uploads)
```

### 5.2 Response Envelope

Every API endpoint returns:

```json
{
    "status": "ok" | "error" | "invalid-token" | "2fa-required",
    "errorMessage": "...",
    "innerErrorMessage": "...",
    "response": { ... }
}
```

### 5.3 HTTPRequest() Callback Map

```
HTTPRequest({
    url:                  string,
    method:               "GET" | "POST",     // default GET
    data:                 string | FormData,
    isTextResponse:       boolean,            // skip JSON parse
    success:              fn(responseJSON),
    error:                fn(),               // network/HTTP error
    invalidToken:         fn(),               // status == "invalid-token"
    twoFactorAuthRequired:fn(),               // status == "2fa-required"
    objAlertPlaceholder:  jQuery,             // where to show error alerts
    objLoaderPlaceholder: jQuery,             // where to show spinner
    processData:          boolean,
    contentType:          string,
    dontHideAlert:        boolean,
    showInnerError:       boolean
})
```

### 5.4 API Namespace Summary

| Namespace | Module | Operations |
|---|---|---|
| `api/user/` | auth.js | login, logout, session get, password change, 2FA, token create, profile, update check |
| `api/admin/users/` | auth.js | list, get, create, set, delete |
| `api/admin/groups/` | auth.js | list, get, create, set, delete |
| `api/admin/permissions/` | auth.js | list, get, set |
| `api/admin/sessions/` | auth.js | list, delete, createToken |
| `api/admin/cluster/` | cluster.js | state, init, initJoin, updateIpAddress, primary/secondary operations |
| `api/settings/` | main.js | get, set, backup, restore, forceUpdateBlockLists, temporaryDisableBlocking, getTsigKeyNames |
| `api/dashboard/` | main.js | stats/get, stats/getTop, stats/deleteAll |
| `api/zones/` | zone.js | list, create, delete, enable, disable, clone, convert, import, export, resync, options/get, options/set, records/*, dnssec/*, permissions/*, catalogs/list |
| `api/cache/` | other-zones.js | list, flush, delete |
| `api/allowed/` | other-zones.js | list, add, delete, flush, import, export |
| `api/blocked/` | other-zones.js | list, add, delete, flush, import, export |
| `api/apps/` | apps.js | list, install, update, uninstall, downloadAndInstall, downloadAndUpdate, listStoreApps, config/get, config/set |
| `api/dnsClient/` | dnsclient.js | resolve |
| `api/dhcp/leases/` | dhcp.js | list, convertToReserved, convertToDynamic, remove |
| `api/dhcp/scopes/` | dhcp.js | list, get, set, enable, disable, delete |
| `api/logs/` | logs.js | list, download, delete, deleteAll, query, export |

---

## 6. UI Patterns

### 6.1 Loader / Content Toggle

Every data panel follows the same two-div pattern:

```html
<div id="divXxxLoader">  ← spinner placeholder (shown during fetch)
<div id="divXxx">        ← actual content (shown after fetch)
```

`HTTPRequest`'s `objLoaderPlaceholder` injects `<img src='img/loader.gif'>` automatically.

### 6.2 Dynamic Table Rendering

All list data is rendered as HTML strings concatenated in a loop and injected via `.html()`:

```javascript
var tableHtmlRows = "";
for (var i = 0; i < items.length; i++) {
    tableHtmlRows += "<tr>...</tr>";
}
$("#tableXxxBody").html(tableHtmlRows);
```

Row IDs use `btoa(name).replace(/=/g, "")` to create stable anchors for in-place updates.

### 6.3 Sub-Views (Zone Editor)

The Zones tab has an internal sub-view pattern: a list view (`#divViewZones`) and an edit view (`#divEditZone`) are toggled by show/hide, not by tab switching. The same pattern exists in DHCP (`#divDhcpViewScopes` / `#divDhcpEditScope`).

### 6.4 Bootstrap Modals

Transient operations (add record, edit zone options, change password, app config, etc.) use Bootstrap 3 modals. They are permanently present in the DOM and activated with `$("#modalXxx").modal("show")`. Alert placeholders inside each modal (`#divXxxAlert`) are scoped to that modal.

### 6.5 Cluster-Aware Dropdowns

Every major section contains a `<select class="cluster-node-dropdown">` allowing the operator to target a specific cluster node. The special value `""` means "all nodes" (write operations) or "the current node" (read operations). `cluster.js` maintains `updateAllClusterNodeDropDowns()` to keep all dropdowns in sync after cluster topology changes.

### 6.6 Persistence via localStorage

| Key | Purpose |
|---|---|
| `"token"` | Session token (persists across page reloads) |
| `"theme"` | `"dark"` or absent (light mode) |
| `"chart_<id>_legend"` | Per-chart legend visibility filters (dashboard) |
| `"optQueryLogsEntriesPerPage"` | Query logs page size preference |

---

## 7. Dashboard & Charting

`main.js` contains `refreshDashboard()` which calls `api/dashboard/stats/get` and renders three types of Chart.js charts:

```
canvasDashboardMain    ← Line chart: queries over time (multi-series)
canvasDashboardPie     ← Doughnut: response type distribution
canvasDashboardPie2    ← Doughnut: query type distribution (top N)
canvasDashboardPie3    ← Doughnut: top clients
```

A 60-second `setInterval` (stored in `refreshTimerHandle`) auto-refreshes when "Last Hour" is selected.

---

## 8. DNS-over-HTTPS Info Page (`dohwww/`)

This is a minimal, separate two-file frontend:

```
dohwww/
├── index.html   ← Static informational page
└── js/
    └── main.js  ← 8-line script; constructs DoH URL from window.location.hostname
```

It references CSS and images from the parent `/css/` and `/img/` paths (served by the same HTTP server). Its only dynamic behaviour:

```javascript
$(function () {
    var link = "https://" + window.location.hostname + "/dns-query";
    $("#lnkDoH").text(link).attr("href", link);
});
```

This page does **not** share any JS with the admin console.

---

## 9. Entity Relationship Diagram

```
┌───────────────────────────────────────────────────────┐
│                     index.html                         │
│  (single page; all markup rendered at document load)   │
│                                                        │
│  ┌──────────┐   ┌─────────────────────────────────┐   │
│  │ #pageLogin│   │           #pageMain              │   │
│  │           │   │  ┌──────────────────────────┐   │   │
│  │ [Login    │   │  │   Bootstrap Tab Set       │   │   │
│  │  Form]    │   │  │  Dashboard│Zones│Settings │   │   │
│  └──────────┘   │  │  Cache│Allowed│Blocked│…  │   │   │
│                 │  └──────────────────────────┘   │   │
│                 │  ┌─────────────────────────┐    │   │
│                 │  │  Bootstrap Modals (×30+) │    │   │
│                 │  └─────────────────────────┘    │   │
│                 └─────────────────────────────────┘   │
└───────────────────────────────────────────────────────┘
        │                          │
        │ DOM manipulation         │ $.ajax (via HTTPRequest)
        ▼                          ▼
┌───────────────┐        ┌──────────────────────┐
│  JS Modules   │        │  Backend HTTP API     │
│ ─────────────-│        │  ────────────────     │
│ common.js     │        │  api/user/…           │
│ auth.js       │        │  api/admin/…          │
│ main.js       │        │  api/settings/…       │
│ zone.js       │        │  api/dashboard/…      │
│ other-zones.js│        │  api/zones/…          │
│ apps.js       │        │  api/cache/…          │
│ dhcp.js       │        │  api/allowed/…        │
│ dnsclient.js  │        │  api/blocked/…        │
│ logs.js       │        │  api/apps/…           │
│ cluster.js    │        │  api/dnsClient/…      │
└───────────────┘        │  api/dhcp/…           │
        │                │  api/logs/…           │
        │ reads/writes   └──────────────────────┘
        ▼
┌───────────────┐
│ localStorage  │
│ ─────────────-│
│ token         │
│ theme         │
│ chart legends │
│ page sizes    │
└───────────────┘
```

---

## 10. Key Architectural Observations

1. **No build toolchain.** Scripts are concatenated by the browser's sequential `<script>` loading. There is no module system, no imports, no bundler.

2. **Global namespace coupling.** All JS functions are global. Modules communicate implicitly through global variables (`sessionData`, `zoneOptionsAvailableTsigKeyNames`, `editZoneInfo`, `appsList`, etc.) and by directly calling functions from other modules.

3. **Token-in-URL pattern.** The auth token is passed as a query-string parameter on every request rather than in an HTTP header. This is a deliberate design choice for compatibility with simple HTTP clients and the backup/download endpoints (`window.open()`).

4. **Permission-driven visibility.** The first action after successful login is reading `sessionData.info.permissions` to show or hide every tab. The server enforces permissions on every API call; the UI hides inaccessible tabs as a UX improvement only.

5. **Cluster-awareness is pervasive.** Every section includes a node selector, and most API calls forward a `node=` parameter. Reads default to the current node; writes go to all nodes or a specific one.

6. **No reactivity layer.** There is no virtual DOM, observable, or data-binding. DOM updates are fully manual: fetch → build HTML string → `$("#target").html(newHtml)`.
