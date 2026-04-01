using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.DnsClient;

public sealed class DnsClientResponse
{
    [JsonPropertyName("result")]
    public DnsClientResult? Result { get; init; }
}

public sealed class DnsClientResult
{
    [JsonPropertyName("status")]
    public string? Status { get; init; }

    [JsonPropertyName("rCode")]
    public string? RCode { get; init; }

    [JsonPropertyName("timeTaken")]
    public int? TimeTaken { get; init; }

    [JsonPropertyName("answer")]
    public List<DnsRecord>? Answer { get; init; }

    [JsonPropertyName("authority")]
    public List<DnsRecord>? Authority { get; init; }

    [JsonPropertyName("additional")]
    public List<DnsRecord>? Additional { get; init; }
}

public sealed class DnsRecord
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; init; } = string.Empty;

    [JsonPropertyName("ttl")]
    public int Ttl { get; init; }

    [JsonPropertyName("rData")]
    public string? RData { get; init; }
}
