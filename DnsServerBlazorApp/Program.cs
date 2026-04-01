using DnsServerBlazorApp.Services;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using MudBlazor;
using MudBlazor.Extensions;
using MudBlazor.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<DnsServerBlazorApp.App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// HttpClient scoped to the same origin (API lives on same host)
builder.Services.AddScoped(sp => new HttpClient
{
    BaseAddress = new Uri(builder.HostEnvironment.BaseAddress)
});

// MudBlazor core + extensions (MudEx)
builder.Services.AddMudServices(config =>
{
    config.SnackbarConfiguration.PositionClass     = Defaults.Classes.Position.TopCenter;
    config.SnackbarConfiguration.PreventDuplicates = false;
    config.SnackbarConfiguration.NewestOnTop       = true;
    config.SnackbarConfiguration.ShowCloseIcon     = true;
    config.SnackbarConfiguration.VisibleStateDuration = 5000;
    config.SnackbarConfiguration.HideTransitionDuration = 300;
    config.SnackbarConfiguration.ShowTransitionDuration = 300;
    config.SnackbarConfiguration.SnackbarVariant    = Variant.Filled;
});
builder.Services.AddMudExtensions();

// App services
builder.Services.AddScoped<SessionService>();
builder.Services.AddScoped<ApiService>();
builder.Services.AddScoped<ThemeService>();

await builder.Build().RunAsync();
