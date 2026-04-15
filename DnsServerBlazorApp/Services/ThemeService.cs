using DnsServerBlazorApp.Infrastructure.Storage;
using DnsServerBlazorApp.Styles;
using MudBlazor;

namespace DnsServerBlazorApp.Services;

/// <summary>
/// Manages dark/light theme toggling.
/// Theme preference is stored in localStorage under the key "theme".
/// </summary>
public sealed class ThemeService
{
    private const string DarkValue  = "dark";
    private const string LightValue = "light";

    private readonly IClientStateStore _store;

    public ThemeService(IClientStateStore store)
    {
        _store = store;
    }

    // ── State ─────────────────────────────────────────────────────────

    public MudTheme  Theme     { get; } = DnsStyling.BuildTheme();
    public bool      IsDarkMode { get; private set; }

    public event Action? OnChange;

    // ── Lifecycle ─────────────────────────────────────────────────────

    /// <summary>Restore theme from localStorage on first render.</summary>
    public async Task InitAsync()
    {
        var stored = await _store.GetAsync<string>(StoreKeys.ThemePreference);
        IsDarkMode = stored == DarkValue;
    }

    /// <summary>Toggle between dark and light mode (mirrors original JS).</summary>
    public async Task ToggleAsync()
    {
        IsDarkMode = !IsDarkMode;
        await PersistAsync();
        OnChange?.Invoke();
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private async Task PersistAsync()
    {
        var value = IsDarkMode ? DarkValue : LightValue;
        await _store.SetAsync(StoreKeys.ThemePreference, value);
    }

}
