using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.DnsClient;

public sealed class DnsClientResponse
{
    [JsonPropertyName("result")]
    public DnsClientResult? Result { get; init; }
}

public sealed class DnsClientResult
{
    // APIDOCS response keys are PascalCase; PropertyNameCaseInsensitive handles matching.

    [JsonPropertyName("Metadata")]
    public DnsResponseMetadata? Metadata { get; init; }

    [JsonPropertyName("RCODE")]
    public string? RCode { get; init; }

    [JsonPropertyName("AuthoritativeAnswer")]
    public bool AuthoritativeAnswer { get; init; }

    [JsonPropertyName("Answer")]
    public List<DnsRecord>? Answer { get; init; }

    [JsonPropertyName("Authority")]
    public List<DnsRecord>? Authority { get; init; }

    [JsonPropertyName("Additional")]
    public List<DnsRecord>? Additional { get; init; }
}

public sealed class DnsResponseMetadata
{
    // e.g. "server1:53 (127.0.0.1:53)"
    [JsonPropertyName("NameServer")]
    public string? NameServer { get; init; }

    [JsonPropertyName("Protocol")]
    public string? Protocol { get; init; }

    // e.g. "45 bytes"
    [JsonPropertyName("DatagramSize")]
    public string? DatagramSize { get; init; }

    // e.g. "1.42 ms"
    [JsonPropertyName("RoundTripTime")]
    public string? RoundTripTime { get; init; }
}

public sealed class DnsRecord
{
    [JsonPropertyName("Name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("Type")]
    public string Type { get; init; } = string.Empty;

    [JsonPropertyName("Class")]
    public string? Class { get; init; }

    // TTL is returned as a human-readable string, e.g. "86400 (1 day)".
    [JsonPropertyName("TTL")]
    public string? Ttl { get; init; }

    // RDATA shape varies by record type (e.g. {"IPAddress":"1.2.3.4"} for A records).
    [JsonPropertyName("RDATA")]
    public JsonElement? RData { get; init; }
}
