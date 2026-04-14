using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Cluster;

/// <summary>
/// Response from api/admin/cluster/state.
/// </summary>
public sealed class ClusterStateResponse
{
    [JsonPropertyName("clusterInitialized")]
    public bool ClusterInitialized { get; set; }

    [JsonPropertyName("dnsServerDomain")]
    public string? DnsServerDomain { get; set; }

    [JsonPropertyName("version")]
    public string? Version { get; set; }

    [JsonPropertyName("clusterDomain")]
    public string? ClusterDomain { get; set; }

    [JsonPropertyName("heartbeatRefreshIntervalSeconds")]
    public int HeartbeatRefreshIntervalSeconds { get; set; }

    [JsonPropertyName("heartbeatRetryIntervalSeconds")]
    public int HeartbeatRetryIntervalSeconds { get; set; }

    [JsonPropertyName("configRefreshIntervalSeconds")]
    public int ConfigRefreshIntervalSeconds { get; set; }

    [JsonPropertyName("configRetryIntervalSeconds")]
    public int ConfigRetryIntervalSeconds { get; set; }

    [JsonPropertyName("configLastSynced")]
    public DateTime? ConfigLastSynced { get; set; }

    // Flat list of all nodes; each node carries its own type ("Primary"/"Secondary")
    // and state ("Self"/"Connected"/"Unreachable").
    [JsonPropertyName("nodes")]
    public List<ClusterNode>? Nodes { get; set; }

    [JsonPropertyName("serverIpAddresses")]
    public List<string>? ServerIpAddresses { get; set; }
}

public sealed class ClusterNode
{
    [JsonPropertyName("id")]
    public long Id { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("ipAddress")]
    public string? IpAddress { get; set; }

    // "Primary" or "Secondary"
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    // "Self" | "Connected" | "Unreachable"
    [JsonPropertyName("state")]
    public string State { get; set; } = string.Empty;

    [JsonPropertyName("lastSeen")]
    public DateTime? LastSeen { get; set; }
}

public sealed class ClusterOptions
{
    [JsonPropertyName("replicationDelay")]
    public int ReplicationDelay { get; set; }

    [JsonPropertyName("resyncRetries")]
    public int ResyncRetries { get; set; }

    [JsonPropertyName("resyncRetryInterval")]
    public int ResyncRetryInterval { get; set; }
}
