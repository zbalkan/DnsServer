namespace DnsServerBlazorApp.Styles;

/// <summary>
/// CSS-like helper class that centralises all design tokens, colour
/// constants, and style-string generators used throughout the Blazor UI.
/// Mirrors the semantic colours from the original main.css while exposing
/// them as strongly-typed C# members that MudBlazor components can consume.
/// </summary>
public static class DnsStyling
{
    // ── Brand ────────────────────────────────────────────────────────────
    public const string Primary        = "#6699ff";
    public const string PrimaryDark    = "#2c2c2e";   // dark-mode app-bar
    public const string FooterBg       = "#f3f3f3";
    public const string FooterBgDark   = "#252525";

    // ── MudBlazor theme palette ───────────────────────────────────────
    /// <summary>Light-mode MudTheme palette for DNS Server branding.</summary>
    public static MudBlazor.MudTheme BuildTheme() => new()
    {
        PaletteLight = new MudBlazor.PaletteLight
        {
            Primary             = Primary,
            PrimaryContrastText = "#ffffff",
            AppbarBackground    = Primary,
            AppbarText          = "#ffffff",
            Background          = "#fafafa",
            Surface             = "#ffffff",
            DrawerBackground    = "#ffffff",
            TextPrimary         = "rgba(0,0,0,.87)",
            TextSecondary       = "rgba(0,0,0,.6)",
            ActionDefault       = "rgba(0,0,0,.54)",
            TableStriped        = "rgba(0,0,0,.02)",
            TableHover          = "rgba(102,153,255,.08)",
            Divider             = "rgba(0,0,0,.12)",
        },
        PaletteDark = new MudBlazor.PaletteDark
        {
            Primary             = Primary,
            PrimaryContrastText = "#ffffff",
            AppbarBackground    = PrimaryDark,
            AppbarText          = "#f5f5f7",
            Background          = "#1a1a1a",
            BackgroundGray      = "#252525",
            Surface             = "#2c2c2e",
            DrawerBackground    = "#2c2c2e",
            TextPrimary         = "#dcdcdc",
            TextSecondary       = "rgba(255,255,255,.6)",
            ActionDefault       = "rgba(255,255,255,.54)",
            TableStriped        = "rgba(255,255,255,.03)",
            TableHover          = "rgba(102,153,255,.12)",
            Divider             = "rgba(255,255,255,.12)",
            DrawerText          = "#dcdcdc",
            DrawerIcon          = "#dcdcdc",
            LinesDefault        = "rgba(255,255,255,.12)",
        },
        Typography = new MudBlazor.Typography
        {
            Default = new MudBlazor.DefaultTypography
            {
                FontFamily = ["Roboto", "Arial", "sans-serif"],
                FontSize   = "14px",
                LineHeight = "1.43",
            }
        },
        LayoutProperties = new MudBlazor.LayoutProperties
        {
            AppbarHeight = "48px",
        }
    };

    // ── Stats-card CSS classes ────────────────────────────────────────
    // Each key maps to a BEM modifier added to .dns-stat-card in app.css.
    public static readonly IReadOnlyDictionary<string, string> StatCardClass =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["TotalQueries"]  = "dns-stat--total",
            ["TotalNoError"]  = "dns-stat--noerror",
            ["ServerFailure"] = "dns-stat--servfail",
            ["NxDomain"]      = "dns-stat--nxdomain",
            ["Refused"]       = "dns-stat--refused",
            ["AuthHit"]       = "dns-stat--auth",
            ["Recursions"]    = "dns-stat--recursive",
            ["CacheHit"]      = "dns-stat--cached",
            ["Blocked"]       = "dns-stat--blocked",
            ["Dropped"]       = "dns-stat--dropped",
            ["Clients"]       = "dns-stat--clients",
        };

    // ── Stats-card raw colours (for Chart.js dataset colours) ─────────
    public static readonly IReadOnlyDictionary<string, string> StatCardColor =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["TotalQueries"]  = "rgba(102,153,255,0.85)",
            ["TotalNoError"]  = "rgba(92,184,92,0.85)",
            ["ServerFailure"] = "rgba(217,83,79,0.85)",
            ["NxDomain"]      = "rgba(120,120,120,0.85)",
            ["Refused"]       = "rgba(91,192,222,0.85)",
            ["AuthHit"]       = "rgba(150,150,0,0.85)",
            ["Recursions"]    = "rgba(23,162,184,0.85)",
            ["CacheHit"]      = "rgba(111,84,153,0.85)",
            ["Blocked"]       = "rgba(255,165,0,0.85)",
            ["Dropped"]       = "rgba(30,30,30,0.85)",
            ["Clients"]       = "rgba(51,122,183,0.85)",
        };

    // ── Zone-type chip colours ────────────────────────────────────────
    public static MudBlazor.Color ZoneTypeColor(string? zoneType) => zoneType switch
    {
        "Primary"            => MudBlazor.Color.Primary,
        "Secondary"          => MudBlazor.Color.Success,
        "Stub"               => MudBlazor.Color.Warning,
        "Forwarder"          => MudBlazor.Color.Info,
        "SecondaryForwarder" => MudBlazor.Color.Secondary,
        "Catalog"            => MudBlazor.Color.Dark,
        "SecondaryCatalog"   => MudBlazor.Color.Dark,
        _                    => MudBlazor.Color.Default,
    };

    public static MudBlazor.Color ZoneStatusColor(bool enabled) =>
        enabled ? MudBlazor.Color.Success : MudBlazor.Color.Error;

    public static MudBlazor.Color DnssecStatusColor(string? dnssecStatus) =>
        dnssecStatus?.ToLowerInvariant() switch
        {
            "signed"    => MudBlazor.Color.Success,
            "unsigned"  => MudBlazor.Color.Default,
            _           => MudBlazor.Color.Default,
        };

    // ── DHCP lease-type chip colours ─────────────────────────────────
    public static MudBlazor.Color LeaseTypeColor(string? leaseType) => leaseType switch
    {
        "Reserved" => MudBlazor.Color.Default,
        "Dynamic"  => MudBlazor.Color.Primary,
        _          => MudBlazor.Color.Default,
    };

    // ── App capability chip colours ───────────────────────────────────
    public const MudBlazor.Color AppCapabilityColor = MudBlazor.Color.Info;

    // ── Style strings for inline use ─────────────────────────────────
    /// <summary>Inline style for a stat card block (legacy fallback).</summary>
    public static string StatCardStyle(string key) =>
        StatCardColor.TryGetValue(key, out var c)
            ? $"background-color:{c};color:#fff;border-radius:4px;padding:6px 8px;"
            : "background-color:rgba(100,100,100,.7);color:#fff;border-radius:4px;padding:6px 8px;";

    /// <summary>Full CSS class string for a stat card.</summary>
    public static string StatCardCss(string key) =>
        "dns-stat-card " + (StatCardClass.TryGetValue(key, out var c) ? c : "dns-stat--total");

    // ── Spacing / sizing constants ────────────────────────────────────
    public const string SmallBtnStyle  = "font-size:12px;padding:2px 0;width:80px;margin-bottom:4px;";
    public const string MedBtnStyle    = "font-size:12px;padding:4px 14px;";
    public const string TableSmallFont = "font-size:13px;";

    // ── Pre-formatted code/JSON block ────────────────────────────────
    public const string CodeBlockStyle =
        "font-family:monospace;font-size:13px;white-space:pre-wrap;word-break:break-all;";
}
