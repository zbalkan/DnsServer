using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Dashboard;

public sealed class DashboardStatsResponse
{
    [JsonPropertyName("stats")]
    public DashboardStats? Stats { get; set; }

    [JsonPropertyName("mainChartData")]
    public DashboardChartData? MainChartData { get; set; }

    [JsonPropertyName("queryResponseChartData")]
    public DashboardChartData? QueryResponseChartData { get; set; }

    [JsonPropertyName("queryTypeChartData")]
    public DashboardChartData? QueryTypeChartData { get; set; }

    [JsonPropertyName("protocolTypeChartData")]
    public DashboardChartData? ProtocolTypeChartData { get; set; }

    [JsonPropertyName("topClients")]
    public List<TopClientStatsEntry>? TopClients { get; set; }

    [JsonPropertyName("topDomains")]
    public List<TopStatsEntry>? TopDomains { get; set; }

    [JsonPropertyName("topBlockedDomains")]
    public List<TopStatsEntry>? TopBlockedDomains { get; set; }
}

public sealed class DashboardStats
{
    // ── Summary counters ──────────────────────────────────────────────
    [JsonPropertyName("totalQueries")]
    public long TotalQueries { get; set; }

    [JsonPropertyName("totalNoError")]
    public long TotalNoError { get; set; }

    [JsonPropertyName("totalServerFailure")]
    public long TotalServerFailure { get; set; }

    [JsonPropertyName("totalNxDomain")]
    public long TotalNxDomain { get; set; }

    [JsonPropertyName("totalRefused")]
    public long TotalRefused { get; set; }

    [JsonPropertyName("totalAuthoritative")]
    public long TotalAuthHit { get; set; }

    [JsonPropertyName("totalRecursive")]
    public long TotalRecursions { get; set; }

    [JsonPropertyName("totalCached")]
    public long TotalCacheHit { get; set; }

    [JsonPropertyName("totalBlocked")]
    public long TotalBlocked { get; set; }

    [JsonPropertyName("totalDropped")]
    public long TotalDropped { get; set; }

    [JsonPropertyName("totalClients")]
    public long TotalClients { get; set; }

    // ── Zone counters ─────────────────────────────────────────────────
    [JsonPropertyName("zones")]
    public long Zones { get; set; }

    [JsonPropertyName("cachedEntries")]
    public long CachedEntries { get; set; }

    [JsonPropertyName("allowedZones")]
    public long AllowedZones { get; set; }

    [JsonPropertyName("blockedZones")]
    public long BlockedZones { get; set; }

    [JsonPropertyName("allowListZones")]
    public long AllowListZones { get; set; }

    [JsonPropertyName("blockListZones")]
    public long BlockListZones { get; set; }

    // ── Derived percentages ───────────────────────────────────────────
    public double NoErrorPct       => Pct(TotalNoError);
    public double ServerFailurePct => Pct(TotalServerFailure);
    public double NxDomainPct      => Pct(TotalNxDomain);
    public double RefusedPct       => Pct(TotalRefused);
    public double AuthHitPct       => Pct(TotalAuthHit);
    public double RecursionsPct    => Pct(TotalRecursions);
    public double CacheHitPct      => Pct(TotalCacheHit);
    public double BlockedPct       => Pct(TotalBlocked);
    public double DroppedPct       => Pct(TotalDropped);

    private double Pct(long v) =>
        TotalQueries > 0 ? Math.Round(v * 100.0 / TotalQueries, 1) : 0;
}

public sealed class DashboardChartData
{
    [JsonPropertyName("labelFormat")]
    public string? LabelFormat { get; set; }

    [JsonPropertyName("labels")]
    public List<string> Labels { get; set; } = [];

    [JsonPropertyName("datasets")]
    public List<DashboardChartDataSet> Datasets { get; set; } = [];
}

public sealed class DashboardChartDataSet
{
    [JsonPropertyName("label")]
    public string? Label { get; set; }

    [JsonPropertyName("data")]
    public List<long> Data { get; set; } = [];
}

public sealed class PieDataPoint
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("hits")]
    public long Hits { get; set; }
}

public class TopStatsEntry
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("nameIdn")]
    public string? NameIdn { get; set; }

    [JsonPropertyName("hits")]
    public long Hits { get; set; }
}

public sealed class TopClientStatsEntry : TopStatsEntry
{
    [JsonPropertyName("domain")]
    public string? Domain { get; set; }

    [JsonPropertyName("rateLimited")]
    public bool RateLimited { get; set; }
}

public sealed class TopStatsResponse
{
    [JsonPropertyName("topClients")]
    public List<TopClientStatsEntry>? TopClients { get; set; }

    [JsonPropertyName("topDomains")]
    public List<TopStatsEntry>? TopDomains { get; set; }

    [JsonPropertyName("topBlockedDomains")]
    public List<TopStatsEntry>? TopBlockedDomains { get; set; }
}
