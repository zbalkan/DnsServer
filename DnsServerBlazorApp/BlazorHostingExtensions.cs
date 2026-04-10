using DnsServerBlazorApp.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using MudBlazor;
using MudBlazor.Extensions;
using MudBlazor.Services;

namespace DnsServerBlazorApp;

/// <summary>
/// Extension methods that let DnsServerCore embed the Blazor UI
/// inside its own WebApplication without coupling the DNS library
/// directly to MudBlazor or other UI packages.
/// </summary>
public static class BlazorHostingExtensions
{
    /// <summary>
    /// Registers Razor component rendering and all Blazor UI services
    /// (MudBlazor, ThemeService, SessionService, ApiService, HttpClient).
    /// Call this on the <see cref="IServiceCollection"/> before building
    /// the <see cref="Microsoft.AspNetCore.Builder.WebApplication"/>.
    /// </summary>
    public static IServiceCollection AddDnsBlazorServices(this IServiceCollection services)
    {
        services.AddRazorComponents()
                .AddInteractiveServerComponents();

        // HttpClient base address resolved per-request from NavigationManager
        // so it always matches the actual origin the browser is using.
        services.AddScoped(sp => new HttpClient
        {
            BaseAddress = new Uri(
                sp.GetRequiredService<NavigationManager>().BaseUri)
        });

        services.AddMudServices(config =>
        {
            config.SnackbarConfiguration.PositionClass           = Defaults.Classes.Position.TopCenter;
            config.SnackbarConfiguration.PreventDuplicates       = false;
            config.SnackbarConfiguration.NewestOnTop             = true;
            config.SnackbarConfiguration.ShowCloseIcon           = true;
            config.SnackbarConfiguration.VisibleStateDuration    = 5000;
            config.SnackbarConfiguration.HideTransitionDuration  = 300;
            config.SnackbarConfiguration.ShowTransitionDuration  = 300;
            config.SnackbarConfiguration.SnackbarVariant         = Variant.Filled;
        });
        services.AddMudExtensions();

        services.AddScoped<SessionService>();
        services.AddScoped<ApiService>();
        services.AddScoped<ThemeService>();

        return services;
    }

    /// <summary>
    /// Maps <see cref="App"/> as the Blazor root component with interactive
    /// server rendering.  Call this after all API route mappings so that
    /// Blazor acts as the fallback for every non-API request.
    /// </summary>
    public static IEndpointRouteBuilder MapDnsBlazorApp(this IEndpointRouteBuilder endpoints)
    {
        // MapStaticAssets() serves _content/* (MudBlazor CSS/JS), _framework/blazor.web.js,
        // and all other static web assets. It requires a build-time manifest generated when
        // DnsServerApp, DnsServerCore, and DnsServerBlazorApp all have StaticWebAssetsEnabled=true.
        // We catch InvalidOperationException so the app still starts if the manifest is absent
        // (e.g. first run before a clean rebuild). In that case _content/* and framework files
        // will be unavailable, but the DNS engine itself keeps running.
        try
        {
            endpoints.MapStaticAssets();
        }
        catch (InvalidOperationException)
        {
            // Manifest not present — do a clean rebuild to generate
            // {EntryAssembly}.staticwebassets.endpoints.json.
        }

        endpoints.MapRazorComponents<App>()
                 .AddInteractiveServerRenderMode();
        return endpoints;
    }
}
