# Technitium DNS Server — Web UI Architecture

## Overview

The Technitium DNS Server admin console is a **Blazor Web App** with Interactive Server rendering, hosted inside `DnsServerCore`. The previous jQuery/Bootstrap SPA (`DnsServerCore/www/`) and the DoH info page (`DnsServerCore/dohwww/`) have been removed and replaced by this Blazor application.

| Project | SDK | Role |
|---|---|---|
| `DnsServerBlazorApp` | `Microsoft.NET.Sdk.Web` | Admin console UI (Blazor components, services, models) |
| `DnsServerCore` | `Microsoft.NET.Sdk` | DNS/DHCP engine + embedded ASP.NET Core host |
| `DnsServerApp` | `Microsoft.NET.Sdk` | Console entry point; starts `DnsWebService` |

`DnsServerCore` references `DnsServerBlazorApp` as a project reference, embedding the UI into the server's own process.

---

## 1. Render Mode

All components use `@rendermode InteractiveServer` (SignalR-based). There is no WebAssembly download. The HTML root is `App.razor`; there is no `wwwroot/index.html`.

```
Browser ──(HTTP)──► DnsServerCore (port 5380)
                     │
                     ├─ /api/*   → REST API handlers (WebService*.cs partial classes)
                     │
                     └─ /*       → Blazor middleware
                                    ├─ Kestrel serves static assets (_content/*, _framework/*)
                                    └─ SignalR hub (/_blazor) keeps component state server-side
```

---

## 2. Hosting Integration

### 2.1 Registration (`AddDnsBlazorServices`)

Called from `DnsWebService.StartWebServiceAsync()` on the `IServiceCollection`:

```csharp
services.AddRazorComponents().AddInteractiveServerComponents();
services.AddScoped<HttpClient>(...);   // base address from NavigationManager.BaseUri
services.AddMudServices(...);          // snackbar, dialog, theming
services.AddMudExtensions();
services.AddScoped<SessionService>();
services.AddScoped<ApiService>();
services.AddScoped<ThemeService>();
```

### 2.2 Endpoint mapping (`MapDnsBlazorApp`)

Called after all `/api/*` routes are registered:

```csharp
// Serve fingerprinted static web assets (MudBlazor CSS/JS, _framework/*)
// Only when the build manifest exists (requires StaticWebAssetsEnabled=true in DnsServerApp.csproj)
if (File.Exists(manifest)) endpoints.MapStaticAssets();

// Mount Blazor as the fallback for all non-API requests
endpoints.MapRazorComponents<App>().AddInteractiveServerRenderMode();
```

**Middleware order** (enforced in `DnsWebService.cs`):
```
UseStaticFiles          ← physical wwwroot (css/app.css, js/app.js, favicon.ico)
UseAntiforgery          ← must be after UseStaticFiles, before MapRazorComponents
[API routes]            ← /api/* handlers
MapStaticAssets()       ← fingerprinted assets (_content/*, _framework/*)
MapRazorComponents<App> ← Blazor fallback
```

---

## 3. Project Layout

```
DnsServerBlazorApp/
├── App.razor                   # HTML root (<head> + <body>, loads CSS/JS)
├── Routes.razor                # <Router> — maps URLs to page components
├── _Imports.razor              # Global @using for all components
├── BlazorHostingExtensions.cs  # AddDnsBlazorServices() + MapDnsBlazorApp()
├── Program.cs                  # Standalone dev entry point (dotnet run)
├── Layout/
│   └── MainLayout.razor        # MudAppBar, user menu, alert banner, footer
├── Pages/
│   ├── Index.razor             # Login form + authenticated tab panel
│   └── Tabs/
│       ├── DashboardTab.razor
│       ├── ZonesTab.razor      # Zone list with EditZoneView sub-view
│       ├── EditZoneView.razor  # Record editor (embedded in ZonesTab)
│       ├── CacheTab.razor
│       ├── AllowedTab.razor
│       ├── BlockedTab.razor
│       ├── AppsTab.razor
│       ├── DnsClientTab.razor
│       ├── SettingsTab.razor
│       ├── AdminTab.razor
│       ├── DhcpTab.razor
│       ├── LogsTab.razor
│       └── AboutTab.razor
├── Shared/
│   ├── ClusterNodeSelect.razor # Node dropdown for cluster-aware tabs
│   ├── StatsCard.razor
│   └── ZoneStatsCard.razor
├── Dialogs/                    # ~18 MudBlazor modal dialogs
├── Services/
│   ├── ApiService.cs           # HTTP wrapper (token, envelope, error handling)
│   ├── SessionService.cs       # Auth state + localStorage persistence
│   └── ThemeService.cs         # Dark/light theme + localStorage + JS interop
├── Models/                     # 13 model files grouped by domain
│   ├── ApiResponse.cs          # ApiResponse<T> JSON envelope + ApiResult<T>
│   ├── Auth/                   # SessionData, UserModels, Permissions, ClusterNodeRef
│   ├── Dashboard/              # DashboardStats
│   ├── Zones/                  # ZoneModels (ZoneInfo, ZoneRecord, ZoneOptions, …)
│   ├── Settings/               # DnsSettings, ProxySettings, TsigKeyEntry, …
│   ├── Dhcp/                   # DhcpModels (DhcpScope, DhcpLease, …)
│   ├── Apps/                   # AppModels
│   ├── Cluster/                # ClusterModels
│   ├── Logs/                   # LogModels
│   ├── Cache/                  # CacheModels
│   └── DnsClient/              # DnsClientModels
├── Styles/
│   └── DnsStyling.cs           # MudTheme builder, zone-type colour map
└── wwwroot/
    ├── css/app.css             # Custom MudBlazor overrides + Blazor error UI
    ├── js/app.js               # window.dnsApp.setBodyClass() for dark mode
    └── favicon.ico             # Browser tab icon
```

---

## 4. Service Layer

### 4.1 ApiService

- Appends `?token=<value>` to every request.
- Deserialises JSON into `ApiResponse<T>` (`status`, `errorMessage`, `response`, `token`, `displayName`, `info`).
- Returns `ApiResult<T>` with flags: `IsOk`, `IsInvalidToken`, `Is2FARequired`, `IsError`, `IsNetworkError`.
- Key methods: `GetAsync<T>`, `PostAsync<T>`, `PostMultipartAsync<T>`, `BuildDownloadUrl`.

### 4.2 SessionService

- Holds the authenticated session in memory; persists `token` in `localStorage`.
- Properties: `IsAuthenticated`, `Token`, `DisplayName`, `Username`, `TotpEnabled`, `Permissions`, `ClusterNodes`.
- Raises `Action? OnChange` on state change; subscribers call `InvokeAsync(StateHasChanged)`.
- Permission helpers: `CanView(section)` / `CanModify(section)`.

### 4.3 ThemeService

- Persists `"theme"` (`"dark"` / `"light"`) in `localStorage`.
- Applies `body.dark-mode` CSS class via `dnsApp.setBodyClass()` JS interop.
- Must call `InitAsync()` from `OnAfterRenderAsync(firstRender)` (JSInterop unavailable during pre-render).

---

## 5. Authentication & Session Flow

```
Browser requests /
       │
       ▼
Index.razor: OnAfterRenderAsync(firstRender)
       │
       ├─ SessionService.LoadStoredTokenAsync()
       │       └─ localStorage has token?
       │               YES → GET api/user/session/get?token=...
       │                       ├─ ok          → IsAuthenticated = true; show tab panel
       │                       ├─ invalid-tok → ClearSessionAsync(); show login
       │                       └─ 2fa-req     → show TOTP input
       │
       └─ NO → show login form
               └─ user submits → POST api/user/login
                       ├─ ok          → SaveSessionAsync(); show tab panel
                       ├─ error       → show error message
                       └─ 2fa-req     → show TOTP input
```

**Token lifecycle:**
- Stored in `localStorage["token"]`
- Appended to every API call as `?token=<value>` by `ApiService`
- On `invalid-token` response: `SessionService.ClearSessionAsync()` + `StateHasChanged`
- On logout: `ClearSessionAsync()` called, then `NavigateTo("/")`

---

## 6. REST API Communication

All API calls go through `ApiService`. The server REST API is documented in `APIDOCS.md`.

### 6.1 Request Pattern

```
GET  /api/<module>/<action>?token=<token>&param=value
POST /api/<module>/<action>?token=<token>
     Content-Type: application/x-www-form-urlencoded
     body: param1=value1&param2=value2
     OR: multipart/form-data  (file uploads)
```

### 6.2 Response Envelope

```json
{
    "status": "ok" | "error" | "invalid-token" | "2fa-required",
    "errorMessage": "...",
    "response": { ... }
}
```

Login response also carries top-level `token`, `displayName`, `username`, `totpEnabled`, `info`.

### 6.3 API Module Summary

| Module | Used by | Operations |
|---|---|---|
| `api/user/` | SessionService, dialogs | login, logout, session get/update, password change, 2FA, token create, profile |
| `api/admin/users/` | AdminTab, AddUserDialog | list, create, set, delete |
| `api/admin/groups/` | AdminTab, AddGroupDialog | list, create, set, delete |
| `api/admin/permissions/` | AdminTab | list, get, set |
| `api/admin/sessions/` | AdminTab | list, revoke |
| `api/admin/cluster/` | AdminTab | state, init, initJoin, update, promote |
| `api/settings/` | SettingsTab | get, set, forceUpdateBlockLists, backup, restore |
| `api/dashboard/` | DashboardTab | stats/get, stats/getTop, stats/deleteAll |
| `api/zones/` | ZonesTab, EditZoneView, dialogs | list, create, delete, enable, disable, options/get, options/set, records/add, records/update, records/delete, dnssec/*, resync |
| `api/cache/` | CacheTab | list, flush, delete |
| `api/allowed/` | AllowedTab, ImportZoneListDialog | list, add, delete, flush, import, export |
| `api/blocked/` | BlockedTab, ImportZoneListDialog | list, add, delete, flush, import, export |
| `api/apps/` | AppsTab, StoreAppsDialog | list, install, update, uninstall, listStoreApps, config/get, config/set |
| `api/dnsClient/` | DnsClientTab | resolve |
| `api/dhcp/leases/` | DhcpTab | list, convertToReserved, convertToDynamic, remove |
| `api/dhcp/scopes/` | DhcpTab, EditDhcpScopeDialog | list, get, set, enable, disable, delete |
| `api/logs/` | LogsTab | list, download, delete, deleteAll, query |

---

## 7. UI Patterns

### 7.1 Tab Visibility (Permissions)

`Index.razor` wraps each `<MudTabPanel>` in `@if (SessionService.CanView("Section"))`. Permissions are populated from the login response and stored in `SessionService.Permissions`.

### 7.2 Cluster-Aware Tabs

Every major tab contains a `<ClusterNodeSelect>` dropdown allowing the operator to target a specific node or "All Nodes (cluster)". The selected value is passed as `node=` in API calls.

### 7.3 Sub-Views

`ZonesTab` embeds `<EditZoneView>` for the record editor, toggled by `_selectedZone` being null/non-null. The same pattern applies to DHCP scopes in `DhcpTab`.

### 7.4 Dialogs

Transient operations use MudBlazor modal dialogs opened via `IDialogService.ShowAsync<TDialog>(...)`. Each dialog has a `[CascadingParameter] IMudDialogInstance` and closes via `MudDialog.Close()` or `MudDialog.Cancel()`.

### 7.5 Filtered Lists

List tabs cache filtered results in a separate `_filtered` field, never using a computed property:

```csharp
private List<ZoneInfo> _filtered = [];

private void UpdateFiltered()
    => _filtered = _zones.Where(z => /* search/filter */).ToList();

// UpdateFiltered() called after: loading data, deleting items, filter input changes
```

### 7.6 Persistence via localStorage

| Key | Service | Purpose |
|---|---|---|
| `"token"` | SessionService | Session token (survives page reloads) |
| `"theme"` | ThemeService | `"dark"` or `"light"` |

---

## 8. Static Assets

| Asset type | Mechanism | Path |
|---|---|---|
| App CSS/JS | Physical `wwwroot/` + `UseStaticFiles()` | `css/app.css`, `js/app.js` |
| MudBlazor CSS/JS | RCL embedded via `MapStaticAssets()` | `_content/MudBlazor/*` |
| Blazor SignalR client | Framework via `MapStaticAssets()` | `_framework/blazor.web.js` |
| Favicon | Physical `wwwroot/favicon.ico` | `favicon.ico` |

`DnsServerApp.csproj` must have `<StaticWebAssetsEnabled>true</StaticWebAssetsEnabled>` to generate the `staticwebassets.endpoints.json` manifest that `MapStaticAssets()` requires.
