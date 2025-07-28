using Microsoft.ML.Data;

namespace DnsSentinelApp.Anomaly
{
    public class DnsAnomalyPrediction
    {
        [ColumnName("IsAnomaly")] public bool IsAnomaly { get; set; }
        [ColumnName("Score")] public float Score { get; set; }
    }
}