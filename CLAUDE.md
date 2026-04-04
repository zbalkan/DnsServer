# CLAUDE.md — Technitium DNS Server

## Overview

Technitium DNS Server is a cross-platform, full-featured DNS server with an integrated web administration console. The solution is written in C# targeting .NET 10 and uses Blazor Web App (Interactive Server rendering) for the UI.

- **License**: GPL v3
- **Target framework**: `net10.0` throughout
- **UI framework**: Blazor Web App (`Microsoft.NET.Sdk.Web`) with MudBlazor 9.x
- **Active dev branch**: `claude/document-dns-architecture-CqgL8` (PR #14)
- **Solution file**: `DnsServer.sln` (35 projects)

---

## Repository Structure

```
DnsServer/
├── DnsServerApp/                 # Console entry point (Exe)
├── DnsServerBlazorApp/           # Blazor Web App — admin console UI
├── DnsServerCore/                # DNS/DHCP engine + HTTP API host
├── DnsServerCore.ApplicationCommon/  # Plugin framework shared types
├── DnsServerCore.HttpApi/        # REST API client library (used by apps)
├── DnsServerSystemTrayApp/       # Windows system tray (Windows Forms)
├── DnsServerWindowsService/      # Windows service wrapper
├── DnsServerWindowsSetup/        # Inno Setup installer project
├── Apps/                         # 27+ DNS application plugins
├── docs/                         # Documentation assets
├── APIDOCS.md                    # Full REST API reference
├── build.md                      # Build instructions
├── Dockerfile / docker-compose.yml
└── DnsServer.sln
```

---

## Project Details

### DnsServerApp
- Console entry point; creates `DnsWebService`, calls `StartAsync()`.
- Handles SIGTERM (Linux) and Ctrl+C for graceful shutdown.
- SDK: `Microsoft.NET.Sdk`, OutputType: `Exe`.

### DnsServerCore
- SDK: `Microsoft.NET.Sdk` (class library, not a runnable host itself).
- Contains the full DNS/DHCP engine plus an embedded ASP.NET Core `WebApplication` host.
- Key files:
  - `DnsWebService.cs` — main orchestrator (~117 KB); creates and runs the `WebApplication`, wires middleware, mounts all API routes and the Blazor UI.
  - `WebService*.cs` partial classes — API surface split by domain: `WebServiceAuthApi`, `WebServiceDashboardApi`, `WebServiceZonesApi`, `WebServiceOtherZonesApi`, `WebServiceAppsApi`, `WebServiceSettingsApi`, `WebServiceDhcpApi`, `WebServiceClusterApi`, `WebServiceLogsApi`.
  - `Auth/` — `AuthManager`, `User`, `Group`, `Permission`, `UserSession`.
  - `Cluster/` — multi-server clustering.
  - `Dhcp/` — full DHCP server.
  - `Dns/` — resolution engine, DNSSEC, zone trees, resource records, app plugin system.
- References TechnitiumLibrary DLLs (shipped in `lib/`), BouncyCastle, QRCoder.
- References `DnsServerBlazorApp` project so publish embeds the UI static assets.

### DnsServerBlazorApp
- SDK: **`Microsoft.NET.Sdk.Web`** (Blazor Web App, not WASM).
- Render mode: **`@rendermode InteractiveServer`** — all components run server-side via SignalR; no WASM download.
- HTML root: `App.razor` (replaces `index.html`). There is no `wwwroot/index.html`.
- Packages: `MudBlazor 9.*`, `MudBlazor.Extensions 9.*`.
- The project is embedded in `DnsServerCore` at runtime; standalone dev mode is also supported via `Program.cs`.

#### Blazor integration points

```csharp
// DnsWebService.cs (in DnsServerCore) calls:
builder.Services.AddDnsBlazorServices();   // registers all UI services
app.MapDnsBlazorApp();                      // mounts Razor components + static files

// Both are extension methods in DnsServerBlazorApp/BlazorHostingExtensions.cs
```

`AddDnsBlazorServices()` registers:
- `AddRazorComponents().AddInteractiveServerComponents()`
- Scoped `HttpClient` (base address from `NavigationManager.BaseUri`)
- `AddMudServices()` + `AddMudExtensions()`
- Scoped services: `SessionService`, `ApiService`, `ThemeService`

`MapDnsBlazorApp()` calls:
- `UseStaticFiles()` / `MapStaticAssets()`
- `UseAntiforgery()` ← **must be between `UseStaticFiles` and `MapRazorComponents`**
- `MapRazorComponents<App>().AddInteractiveServerRenderMode()`

#### Directory layout

```
DnsServerBlazorApp/
├── App.razor                   # HTML root (head + body, loads scripts/CSS)
├── Routes.razor                # <Router> component
├── _Imports.razor              # Global @using statements for all components
├── BlazorHostingExtensions.cs  # AddDnsBlazorServices() + MapDnsBlazorApp()
├── Program.cs                  # Standalone dev entry point
├── Layout/
│   └── MainLayout.razor        # MudAppBar, user menu, alert banner, footer
├── Pages/
│   ├── Index.razor             # Login form + tab panel (authenticated view)
│   └── Tabs/
│       ├── DashboardTab.razor
│       ├── ZonesTab.razor      # Zone list with pagination + inline EditZoneView
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
│   ├── ClusterNodeSelect.razor
│   ├── StatsCard.razor
│   └── ZoneStatsCard.razor
├── Dialogs/                    # 18 MudBlazor modal dialogs
├── Services/
│   ├── ApiService.cs           # HTTP wrapper with token + envelope handling
│   ├── SessionService.cs       # Auth state + localStorage persistence
│   └── ThemeService.cs         # Dark/light theme + localStorage persistence
├── Models/                     # 13 model files organized by domain
│   ├── ApiResponse.cs          # Generic ApiResponse<T> JSON envelope
│   ├── Auth/
│   ├── Dashboard/
│   ├── Zones/
│   ├── Settings/
│   ├── Dhcp/
│   ├── Apps/
│   ├── Cluster/
│   ├── Logs/
│   ├── Cache/
│   └── DnsClient/
├── Styles/
│   └── DnsStyling.cs           # MudTheme builder, zone-type colors
└── wwwroot/
    ├── css/app.css             # Custom MudBlazor overrides + Blazor error UI
    ├── js/app.js               # window.dnsApp.setBodyClass() for dark mode
    └── img/                    # Logos and icons
```

---

## Service Layer

### ApiService
Wraps all HTTP calls to the Technitium REST API.

- Attaches session token to every request (`?token=...`).
- Deserialises JSON into `ApiResponse<T>` envelope (fields: `status`, `errorMessage`, `response`, `token`, `displayName`, `info`).
- Returns `ApiResult<T>` with typed flags: `IsOk`, `IsInvalidToken`, `Is2FARequired`, `IsError`, `IsNetworkError`.
- Key methods: `GetAsync<T>(path)`, `PostAsync<T>(path, form)`, `PostMultipartAsync<T>(path, form)`, `BuildDownloadUrl(path)`.

### SessionService
- Holds the authenticated session in memory; persists `token` in `localStorage`.
- Exposes: `IsAuthenticated`, `Token`, `DisplayName`, `Username`, `TotpEnabled`, `Permissions`, `ClusterNodes`.
- Raises `Action? OnChange` when auth state changes — subscribers call `InvokeAsync(StateHasChanged)`.
- Permission helpers: `CanView(section)` / `CanModify(section)` — valid sections: `Dashboard`, `Zones`, `Cache`, `Allowed`, `Blocked`, `Apps`, `DnsClient`, `Settings`, `DhcpServer`, `Administration`, `Logs`.

### ThemeService
- Persists `"theme"` (`"dark"` / `"light"`) in `localStorage`.
- Applies `body.dark-mode` CSS class via `dnsApp.setBodyClass()` JS interop.
- Raises `Action? OnChange` — same subscription pattern as `SessionService`.
- Must call `InitAsync()` in `OnAfterRenderAsync(firstRender)` (JSInterop unavailable during pre-render).

---

## Key Conventions

### Blazor component patterns

**Event unsubscription** — always implement `IDisposable` when subscribing to service events:
```csharp
@implements IDisposable

protected override async Task OnAfterRenderAsync(bool firstRender)
{
    if (firstRender)
    {
        ThemeService.OnChange   += OnServiceChanged;
        SessionService.OnChange += OnServiceChanged;
    }
}

private void OnServiceChanged() => InvokeAsync(StateHasChanged);

public void Dispose()
{
    ThemeService.OnChange   -= OnServiceChanged;
    SessionService.OnChange -= OnServiceChanged;
}
```

**No fire-and-forget** — never use `_ = SomeAsync()`. Use proper `async` lambdas or named methods:
```razor
@* WRONG *@
OnKeyUp="@(e => { if(e.Key=="Enter") _ = DoLoginAsync(); })"
ValueChanged="@((v) => { _node = v; _ = LoadAsync(); })"

@* CORRECT *@
OnKeyUp="@(async e => { if(e.Key=="Enter") await DoLoginAsync(); })"
ValueChanged="OnNodeChangedAsync"
```

**Race-condition guard** — when loading detail data after a selection, discard stale responses:
```csharp
private async Task SelectZone(string zone)
{
    _selected = zone;
    _loadingRecords = true;
    var result = await Api.GetAsync<...>(...);

    if (_selected != zone) return; // discard stale response
    _loadingRecords = false;
    _records = result.IsOk ? result.Data?.Records ?? [] : [];
}
```

**Cached filter fields** — never use a `=>` computed property for filtered lists; cache in a field updated on data load and filter changes:
```csharp
private List<ZoneInfo> _filtered = [];

private void UpdateFiltered()
{
    _filtered = _zones.Where(z => ...).ToList();
}

// Call UpdateFiltered() after loading _zones and when filter inputs change.
```

**File downloads** — use `NavigationManager.NavigateTo(url, forceLoad: true)`:
```csharp
private void ExportAsync()
{
    var url = Api.BuildDownloadUrl($"api/allowed/export?node={Uri.EscapeDataString(_node)}");
    Nav.NavigateTo(url, forceLoad: true);
}
```

### CSS / markup conventions

- **Toolbar rows**: use `class="dns-toolbar"` instead of inline `style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px;"`.
- Other named CSS classes in `app.css`: `dns-stats-strip`, `dns-stat-card`, `dns-zone-stats-strip`, `dns-panel-header-row`, `dns-split-container`, `dns-split-left`, `dns-split-right`, `dns-toolbar`, `dns-code-block`, `dns-alert-placeholder`.
- Dark mode: MudBlazor `IsDarkMode` prop + `body.dark-mode` CSS class for custom overrides in `app.css`.

### No logic in Razor markup

Keep `@code` blocks focused on UI state and event wiring. Move business logic, API calls, and data transformation into service classes or private methods. Razor markup should only reference state and call handlers.

### YAGNI / KISS

- No speculative abstractions — three similar lines are better than a premature helper.
- Only validate at system boundaries (user input, API responses); trust internal framework guarantees.
- Do not add error handling for scenarios that cannot happen.
- No backwards-compatibility shims for code that is no longer used.

---

## REST API

The REST API is documented in `APIDOCS.md`. All endpoints follow the pattern:

```
GET  /api/{module}/{action}?token=<token>&...params
POST /api/{module}/{action}        (form-encoded body, token optional in body)
```

JSON response envelope:
```json
{ "status": "ok|error|invalid-token|2fa-required",
  "errorMessage": "...",
  "response": { ... } }
```

Login response also includes top-level `token`, `displayName`, `username`, `totpEnabled`, `info`.

Key modules: `user`, `dashboard`, `zones`, `zones/records`, `allowed`, `blocked`, `cache`, `apps`, `settings`, `dhcp`, `logs`, `cluster`, `admin`.

**Validating API response shapes**: use `DnsServerCore.HttpApi/` source or `APIDOCS.md` — do not guess field names.

---

## Build

```bash
# Linux / macOS
dotnet publish DnsServerApp/DnsServerApp.csproj -c Release

# Docker
docker build -t technitium/dns-server:latest .
docker compose up

# Windows
# Open DnsServer.sln in Visual Studio, build in Release mode
# Windows installer requires Inno Setup (see build.md)
```

There is no Makefile. Full instructions are in `build.md`.

---

## Development Workflow

### Running the Blazor UI standalone (no DNS engine)
```bash
cd DnsServerBlazorApp
dotnet run
# Opens on http://localhost:5000 — points API calls at the same origin
```
Set the DNS server URL via `NavigationManager.BaseUri` configuration if a real DNS server is running elsewhere.

### Running the full server
```bash
cd DnsServerApp
dotnet run
# Web console: http://localhost:5380
```

### Adding a new tab
1. Create `Pages/Tabs/MyTab.razor`.
2. Add `@inject` directives for `ApiService`, `SessionService`, etc.
3. Add `<MudTabPanel Text="MyTab" ID="@("MyTab")">` in `Index.razor` wrapped in `@if (SessionService.CanView("MySection"))`.
4. Add the section name to `SessionService.CanView()` and `CanModify()` switches if it requires permission gating.

### Adding a new dialog
1. Create `Dialogs/MyDialog.razor` with `[CascadingParameter] IMudDialogInstance MudDialog { get; set; } = null!;`.
2. Open via `await DialogService.ShowAsync<MyDialog>("Title", parameters, options)`.
3. Close via `MudDialog.Close()` / `MudDialog.Cancel()`.

### Adding a new model
1. Create under `Models/{Domain}/` using `System.Text.Json` attributes (`[JsonPropertyName("...")]`).
2. Make collection properties nullable where the API may omit them.
3. Validate field names against `APIDOCS.md` or `DnsServerCore.HttpApi/` source — the API envelope uses camelCase JSON.

---

## Important Constraints

- **No `index.html`** — the app uses `App.razor` as the HTML root. Do not create `wwwroot/index.html`.
- **No `Microsoft.NET.Sdk.BlazorWebAssembly`** — the project was migrated to `Microsoft.NET.Sdk.Web` with InteractiveServer rendering. WASM-specific APIs (`WebAssemblyHostBuilder`, `IWebAssemblyHostEnvironment`, `Microsoft.AspNetCore.Components.WebAssembly.*`) must not be used.
- **`UseAntiforgery()` placement** — it must be called after `UseStaticFiles()` and before `MapRazorComponents()` in the middleware pipeline.
- **JSInterop only after first render** — `SessionService.LoadStoredTokenAsync()` and `ThemeService.InitAsync()` call `localStorage`; they must be called from `OnAfterRenderAsync(firstRender)` or `OnInitializedAsync` (which runs after pre-render on Interactive Server).
- **`InvokeAsync(StateHasChanged)`** — always wrap `StateHasChanged` calls in `InvokeAsync` when triggered from background threads or event callbacks (timer callbacks, service event handlers).
- **Do not remove the `www/` or `dohwww/` directories** — they were already removed. `DnsServerCore.csproj` no longer references them.
- **Token security** — the token is appended as a query parameter by `ApiService.BuildUrl()`; never log full API URLs in production code.
