using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Cache;

public sealed class CacheListResponse
{
    [JsonPropertyName("zones")]
    public List<string>? Zones { get; init; }
}

public sealed class CacheViewResponse
{
    [JsonPropertyName("text")]
    public string? Text { get; init; }
}
