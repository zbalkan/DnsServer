using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Cluster;

public sealed class ClusterStateResponse
{
    [JsonPropertyName("initialized")]
    public bool Initialized { get; set; }

    [JsonPropertyName("primaryNode")]
    public ClusterNode? PrimaryNode { get; set; }

    [JsonPropertyName("secondaryNodes")]
    public List<ClusterNode>? SecondaryNodes { get; set; }

    [JsonPropertyName("selfNode")]
    public ClusterNode? SelfNode { get; set; }
}

public sealed class ClusterNode
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("primaryAddress")]
    public string? PrimaryAddress { get; set; }

    [JsonPropertyName("selfNodeIpAddresses")]
    public List<string>? SelfNodeIpAddresses { get; set; }

    [JsonPropertyName("primaryNodeIpAddresses")]
    public List<string>? PrimaryNodeIpAddresses { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;   // Online | Offline | Syncing

    [JsonPropertyName("lastSeen")]
    public DateTime? LastSeen { get; set; }

    [JsonPropertyName("version")]
    public string? Version { get; set; }
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
