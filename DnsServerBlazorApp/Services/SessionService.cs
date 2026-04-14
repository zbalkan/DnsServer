using DnsServerBlazorApp.Models.Auth;
using Microsoft.JSInterop;

namespace DnsServerBlazorApp.Services;

/// <summary>
/// Holds the authenticated session and persists the token in localStorage.
/// Raises <see cref="OnChange"/> whenever auth state changes so components
/// can call <c>StateHasChanged()</c>.
/// </summary>
public sealed class SessionService
{
    private readonly IJSRuntime            _js;
    private readonly ILogger<SessionService> _logger;

    public SessionService(IJSRuntime js, ILogger<SessionService> logger)
    {
        _js     = js;
        _logger = logger;
    }

    // ── State ─────────────────────────────────────────────────────────

    public SessionData? Session    { get; private set; }
    public bool IsAuthenticated    => Session is not null;
    public string  Token           => Session?.Token ?? string.Empty;
    public string  DisplayName     => Session?.DisplayName ?? string.Empty;
    public string  Username        => Session?.Username ?? string.Empty;
    public bool    TotpEnabled     => Session?.TotpEnabled ?? false;
    public ServerInfo? Info        => Session?.Info;
    public Permissions Permissions => Session?.Info?.Permissions ?? new();

    /// <summary>Cluster nodes list (updated when settings or session refreshes).</summary>
    public List<ClusterNodeRef> ClusterNodes =>
        Session?.Info?.ClusterNodes ?? [];

    // ── Events ────────────────────────────────────────────────────────

    public event Action? OnChange;

    // ── Lifecycle ─────────────────────────────────────────────────────

    /// <summary>
    /// Load the stored token from localStorage.
    /// Returns null if none is stored.
    /// </summary>
    public async Task<string?> LoadStoredTokenAsync()
    {
        try
        {
            return await _js.InvokeAsync<string?>("localStorage.getItem", "token");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "JS interop unavailable loading token (SSR pre-render or storage error)");
            return null;
        }
    }

    /// <summary>Store a new session after successful login / session-get.</summary>
    public async Task SetSessionAsync(SessionData data)
    {
        Session = data;
        await PersistTokenAsync(data.Token);
        Notify();
    }

    /// <summary>Update display name in the current session (called after profile save).</summary>
    public void UpdateDisplayName(string name)
    {
        if (Session is null) return;
        Session.DisplayName = name;
        Notify();
    }

    /// <summary>Update TOTP-enabled flag (called after 2FA enable/disable).</summary>
    public void UpdateTotpEnabled(bool enabled)
    {
        if (Session is null) return;
        Session.TotpEnabled = enabled;
        Notify();
    }

    /// <summary>Update cluster node list (called after refreshing settings).</summary>
    public void UpdateClusterNodes(List<ClusterNodeRef> nodes)
    {
        if (Session?.Info is null) return;
        Session.Info.ClusterNodes = nodes;
        Notify();
    }

    /// <summary>Clear session on logout or invalid token.</summary>
    public async Task ClearSessionAsync()
    {
        Session = null;
        await RemoveTokenAsync();
        Notify();
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private async Task PersistTokenAsync(string token)
    {
        try { await _js.InvokeVoidAsync("localStorage.setItem", "token", token); }
        catch (Exception ex) { _logger.LogDebug(ex, "JS interop unavailable persisting token (SSR pre-render or storage error)"); }
    }

    private async Task RemoveTokenAsync()
    {
        try { await _js.InvokeVoidAsync("localStorage.removeItem", "token"); }
        catch (Exception ex) { _logger.LogDebug(ex, "JS interop unavailable removing token (SSR pre-render or storage error)"); }
    }

    private void Notify() => OnChange?.Invoke();

    // ── Permission shorthands ─────────────────────────────────────────

    public bool CanView(string section) => section switch
    {
        "Dashboard"      => Permissions.Dashboard.CanView,
        "Zones"          => Permissions.Zones.CanView,
        "Cache"          => Permissions.Cache.CanView,
        "Allowed"        => Permissions.Allowed.CanView,
        "Blocked"        => Permissions.Blocked.CanView,
        "Apps"           => Permissions.Apps.CanView,
        "DnsClient"      => Permissions.DnsClient.CanView,
        "Settings"       => Permissions.Settings.CanView,
        "DhcpServer"     => Permissions.DhcpServer.CanView,
        "Administration" => Permissions.Administration.CanView,
        "Logs"           => Permissions.Logs.CanView,
        _                => false,
    };

    public bool CanModify(string section) => section switch
    {
        "Dashboard"      => Permissions.Dashboard.CanModify,
        "Zones"          => Permissions.Zones.CanModify,
        "Cache"          => Permissions.Cache.CanModify,
        "Allowed"        => Permissions.Allowed.CanModify,
        "Blocked"        => Permissions.Blocked.CanModify,
        "Apps"           => Permissions.Apps.CanModify,
        "DnsClient"      => Permissions.DnsClient.CanModify,
        "Settings"       => Permissions.Settings.CanModify,
        "DhcpServer"     => Permissions.DhcpServer.CanModify,
        "Administration" => Permissions.Administration.CanModify,
        "Logs"           => Permissions.Logs.CanModify,
        _                => false,
    };
}
