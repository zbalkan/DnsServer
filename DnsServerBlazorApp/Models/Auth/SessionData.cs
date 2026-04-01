using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Auth;

/// <summary>
/// Full session payload returned by api/user/login and api/user/session/get.
/// Mirrors the JavaScript sessionData object stored in localStorage.
/// </summary>
public sealed class SessionData
{
    [JsonPropertyName("token")]
    public string Token { get; set; } = string.Empty;

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("displayName")]
    public string DisplayName { get; set; } = string.Empty;

    [JsonPropertyName("totpEnabled")]
    public bool TotpEnabled { get; set; }

    [JsonPropertyName("info")]
    public ServerInfo Info { get; set; } = new();
}

public sealed class ServerInfo
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    [JsonPropertyName("dnsServerDomain")]
    public string DnsServerDomain { get; set; } = string.Empty;

    [JsonPropertyName("uptimestamp")]
    public DateTime Uptimestamp { get; set; }

    [JsonPropertyName("useSoaSerialDateScheme")]
    public bool UseSoaSerialDateScheme { get; set; }

    [JsonPropertyName("dnssecValidation")]
    public bool DnssecValidation { get; set; }

    [JsonPropertyName("defaultRecordTtl")]
    public int DefaultRecordTtl { get; set; } = 3600;

    [JsonPropertyName("defaultNsRecordTtl")]
    public int DefaultNsRecordTtl { get; set; } = 3600;

    [JsonPropertyName("defaultSoaRecordTtl")]
    public int DefaultSoaRecordTtl { get; set; } = 3600;

    [JsonPropertyName("clusterInitialized")]
    public bool ClusterInitialized { get; set; }

    [JsonPropertyName("clusterDomain")]
    public string? ClusterDomain { get; set; }

    [JsonPropertyName("clusterNodes")]
    public List<ClusterNodeRef>? ClusterNodes { get; set; }

    [JsonPropertyName("permissions")]
    public Permissions Permissions { get; set; } = new();
}

public sealed class ClusterNodeRef
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("isPrimary")]
    public bool IsPrimary { get; set; }
}
