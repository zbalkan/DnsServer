using DnsServerBlazorApp.Services;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
        services.AddHttpContextAccessor();

        services.AddScoped<CircuitHandler, LoggingCircuitHandler>();

        services.AddRazorComponents()
                .AddInteractiveServerComponents();

        services.TryAddScoped<HttpClient>();

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
        // If the manifest is absent the exception is intentionally allowed to propagate so the
        // broken-UI condition is visible immediately rather than silently at runtime.
        endpoints.MapStaticAssets();

        endpoints.MapRazorComponents<App>()
                 .AddInteractiveServerRenderMode();

        return endpoints;
    }

    private sealed class LoggingCircuitHandler(ILogger<LoggingCircuitHandler> logger) : CircuitHandler
    {
        public override Task OnCircuitClosedAsync(Circuit circuit, CancellationToken cancellationToken)
        {
            logger.LogInformation("Blazor circuit closed: {CircuitId}", circuit.Id);
            return Task.CompletedTask;
        }

        public override Task OnConnectionDownAsync(Circuit circuit, CancellationToken cancellationToken)
        {
            logger.LogWarning("Blazor connection down: {CircuitId}", circuit.Id);
            return Task.CompletedTask;
        }

        public override Task OnConnectionUpAsync(Circuit circuit, CancellationToken cancellationToken)
        {
            logger.LogInformation("Blazor connection up: {CircuitId}", circuit.Id);
            return Task.CompletedTask;
        }

        public override Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
        {
            logger.LogInformation("Blazor circuit opened: {CircuitId}", circuit.Id);
            return Task.CompletedTask;
        }
    }
}
