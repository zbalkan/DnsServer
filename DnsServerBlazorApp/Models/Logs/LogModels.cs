using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Logs;

public sealed class LogFilesResponse
{
    [JsonPropertyName("logFiles")]
    public List<LogFile> LogFiles { get; set; } = [];
}

public sealed class LogFile
{
    [JsonPropertyName("fileName")]
    public string FileName { get; set; } = string.Empty;

    [JsonPropertyName("size")]
    public string Size { get; set; } = string.Empty;
}

public sealed class QueryLogsResponse
{
    [JsonPropertyName("pageNumber")]
    public int PageNumber { get; set; }

    [JsonPropertyName("totalPages")]
    public int TotalPages { get; set; }

    [JsonPropertyName("totalEntries")]
    public int TotalEntries { get; set; }

    [JsonPropertyName("entries")]
    public List<QueryLogEntry> Entries { get; set; } = [];
}

public sealed class QueryLogEntry
{
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    [JsonPropertyName("clientIpAddress")]
    public string ClientIpAddress { get; set; } = string.Empty;

    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = string.Empty;

    [JsonPropertyName("qname")]
    public string Qname { get; set; } = string.Empty;

    [JsonPropertyName("qtype")]
    public string Qtype { get; set; } = string.Empty;

    [JsonPropertyName("responseType")]
    public string ResponseType { get; set; } = string.Empty;

    [JsonPropertyName("rcode")]
    public string Rcode { get; set; } = string.Empty;

    [JsonPropertyName("rowNumber")]
    public int RowNumber { get; set; }

    [JsonPropertyName("responseRtt")]
    public double? ResponseRtt { get; set; }

    [JsonPropertyName("qclass")]
    public string? QClass { get; set; }

    [JsonPropertyName("answer")]
    public string? Answer { get; set; }
}

public sealed class QueryLogsAppsResponse
{
    [JsonPropertyName("apps")]
    public List<QueryLogsApp> Apps { get; set; } = [];
}

public sealed class QueryLogsApp
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("dnsApps")]
    public List<QueryLogsAppClass> DnsApps { get; set; } = [];
}

public sealed class QueryLogsAppClass
{
    [JsonPropertyName("classPath")]
    public string ClassPath { get; set; } = string.Empty;

    [JsonPropertyName("isQueryLogs")]
    public bool IsQueryLogs { get; set; }
}
