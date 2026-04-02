using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Cache;

public sealed class CacheListResponse
{
    [JsonPropertyName("zones")]
    public List<string>? Zones { get; init; }
}

