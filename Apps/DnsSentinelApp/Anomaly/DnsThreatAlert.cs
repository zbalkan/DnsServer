using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace DnsSentinelApp.Anomaly
{
    public class DnsThreatAlert
    {
        [JsonPropertyName("actionTaken")] public PolicyAction ActionTaken { get; set; }
        [JsonPropertyName("alertId")] public Guid AlertId { get; } = Guid.NewGuid();
        [JsonPropertyName("iocs")] public List<Ioc> Iocs { get; set; } = new List<Ioc>();
        [JsonPropertyName("justification")] public string Justification { get; set; }
        [JsonPropertyName("suspectedAttackType")] public string SuspectedAttackType { get; set; }
        [JsonPropertyName("threatLevel")] public ThreatLevel ThreatLevel { get; set; }
        [JsonPropertyName("threatScore")] public int ThreatScore { get; set; }
        [JsonPropertyName("timestampUtc")] public DateTime TimestampUtc { get; } = DateTime.UtcNow;
    }
}