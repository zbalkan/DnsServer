// Standalone development entry point.
// In production the DNS web service (DnsServerCore.DnsWebService) hosts the
// Blazor UI directly inside its own WebApplication via the extension methods
// in BlazorHostingExtensions.  This file lets developers run the UI on its own
// against a separately-running DNS API server.

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDnsBlazorServices();

var app = builder.Build();

app.UseStaticFiles();
app.UseAntiforgery();
app.MapDnsBlazorApp();

app.Run();
