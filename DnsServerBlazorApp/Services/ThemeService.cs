using DnsServerBlazorApp.Styles;
using Microsoft.JSInterop;
using MudBlazor;

namespace DnsServerBlazorApp.Services;

/// <summary>
/// Manages dark/light theme toggling.
/// Theme preference is stored in localStorage under the key "theme".
/// </summary>
public sealed class ThemeService
{
    private const string StorageKey = "theme";
    private const string DarkValue  = "dark";

    private readonly IJSRuntime          _js;
    private readonly ILogger<ThemeService> _logger;

    public ThemeService(IJSRuntime js, ILogger<ThemeService> logger)
    {
        _js     = js;
        _logger = logger;
    }

    // ── State ─────────────────────────────────────────────────────────

    public MudTheme  Theme     { get; } = DnsStyling.BuildTheme();
    public bool      IsDarkMode { get; private set; }

    public event Action? OnChange;

    // ── Lifecycle ─────────────────────────────────────────────────────

    /// <summary>Restore theme from localStorage on first render.</summary>
    public async Task InitAsync()
    {
        try
        {
            var stored = await _js.InvokeAsync<string?>("localStorage.getItem", StorageKey);
            IsDarkMode = stored == DarkValue;
        }
        catch (Exception ex) { _logger.LogDebug(ex, "JS interop unavailable loading theme (SSR pre-render or storage error)"); }
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
        try
        {
            var value = IsDarkMode ? DarkValue : "light";
            await _js.InvokeVoidAsync("localStorage.setItem", StorageKey, value);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "JS interop unavailable persisting theme (SSR pre-render or storage error)"); }
    }
}
