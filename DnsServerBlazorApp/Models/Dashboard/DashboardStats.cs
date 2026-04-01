using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Dashboard;

public sealed class DashboardStatsResponse
{
    [JsonPropertyName("stats")]
    public DashboardStats Stats { get; set; } = new();
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

    [JsonPropertyName("totalAuthHit")]
    public long TotalAuthHit { get; set; }

    [JsonPropertyName("totalRecursions")]
    public long TotalRecursions { get; set; }

    [JsonPropertyName("totalCacheHit")]
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

    // ── Time-series chart data ────────────────────────────────────────
    [JsonPropertyName("mainChartData")]
    public List<ChartDataPoint> MainChartData { get; set; } = [];

    // ── Response-type pie data ────────────────────────────────────────
    [JsonPropertyName("queryResponseChartData")]
    public List<PieDataPoint> QueryResponseChartData { get; set; } = [];

    [JsonPropertyName("queryTypeChartData")]
    public List<PieDataPoint> QueryTypeChartData { get; set; } = [];

    [JsonPropertyName("queryProtocolChartData")]
    public List<PieDataPoint> QueryProtocolChartData { get; set; } = [];

    // ── Top-N tables ─────────────────────────────────────────────────
    [JsonPropertyName("topClients")]
    public List<TopStatsEntry> TopClients { get; set; } = [];

    [JsonPropertyName("topDomains")]
    public List<TopStatsEntry> TopDomains { get; set; } = [];

    [JsonPropertyName("topBlockedDomains")]
    public List<TopStatsEntry> TopBlockedDomains { get; set; } = [];

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

public sealed class ChartDataPoint
{
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

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

    [JsonPropertyName("totalAuthHit")]
    public long TotalAuthHit { get; set; }

    [JsonPropertyName("totalRecursions")]
    public long TotalRecursions { get; set; }

    [JsonPropertyName("totalCacheHit")]
    public long TotalCacheHit { get; set; }

    [JsonPropertyName("totalBlocked")]
    public long TotalBlocked { get; set; }

    [JsonPropertyName("totalDropped")]
    public long TotalDropped { get; set; }
}

public sealed class PieDataPoint
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("hits")]
    public long Hits { get; set; }
}

public sealed class TopStatsEntry
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("hits")]
    public long Hits { get; set; }
}

public sealed class TopStatsResponse
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("stats")]
    public List<TopStatsEntry> Stats { get; set; } = [];
}
