using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Apps;

public sealed class AppsListResponse
{
    [JsonPropertyName("apps")]
    public List<DnsApp> Apps { get; set; } = [];
}

public sealed class DnsApp
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    [JsonPropertyName("updateVersion")]
    public string? UpdateVersion { get; set; }

    [JsonPropertyName("updateUrl")]
    public string? UpdateUrl { get; set; }

    [JsonPropertyName("updateAvailable")]
    public bool UpdateAvailable { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("dnsApps")]
    public List<DnsAppClass> DnsApps { get; set; } = [];
}

public sealed class DnsAppClass
{
    [JsonPropertyName("classPath")]
    public string ClassPath { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("recordDataTemplate")]
    public string? RecordDataTemplate { get; set; }

    [JsonPropertyName("isAppRecordRequestHandler")]
    public bool IsAppRecordRequestHandler { get; set; }

    [JsonPropertyName("isRequestController")]
    public bool IsRequestController { get; set; }

    [JsonPropertyName("isAuthoritativeRequestHandler")]
    public bool IsAuthoritativeRequestHandler { get; set; }

    [JsonPropertyName("isRequestBlockingHandler")]
    public bool IsRequestBlockingHandler { get; set; }

    [JsonPropertyName("isQueryLogger")]
    public bool IsQueryLogger { get; set; }

    [JsonPropertyName("isQueryLogs")]
    public bool IsQueryLogs { get; set; }

    [JsonPropertyName("isPostProcessor")]
    public bool IsPostProcessor { get; set; }
}

public sealed class StoreAppsListResponse
{
    [JsonPropertyName("storeApps")]
    public List<StoreApp> StoreApps { get; set; } = [];
}

public sealed class StoreApp
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;

    [JsonPropertyName("size")]
    public string Size { get; set; } = string.Empty;

    [JsonPropertyName("installed")]
    public bool Installed { get; set; }

    [JsonPropertyName("installedVersion")]
    public string? InstalledVersion { get; set; }

    [JsonPropertyName("updateAvailable")]
    public bool UpdateAvailable { get; set; }
}

public sealed class AppConfigResponse
{
    [JsonPropertyName("config")]
    public string Config { get; set; } = string.Empty;
}

public sealed class InstalledAppResponse
{
    [JsonPropertyName("installedApp")]
    public DnsApp? InstalledApp { get; set; }

    [JsonPropertyName("updatedApp")]
    public DnsApp? UpdatedApp { get; set; }
}
