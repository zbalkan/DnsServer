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
    public long Size { get; set; }
}

public sealed class LogViewResponse
{
    [JsonPropertyName("fileName")]
    public string FileName { get; set; } = string.Empty;

    [JsonPropertyName("offset")]
    public long Offset { get; set; }

    [JsonPropertyName("length")]
    public long Length { get; set; }

    [JsonPropertyName("entries")]
    public List<string> Entries { get; set; } = [];
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

    [JsonPropertyName("clientAddress")]
    public string ClientAddress { get; set; } = string.Empty;

    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = string.Empty;

    [JsonPropertyName("question")]
    public string Question { get; set; } = string.Empty;

    [JsonPropertyName("queryType")]
    public string QueryType { get; set; } = string.Empty;

    [JsonPropertyName("responseType")]
    public string ResponseType { get; set; } = string.Empty;

    [JsonPropertyName("rcode")]
    public string Rcode { get; set; } = string.Empty;

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
