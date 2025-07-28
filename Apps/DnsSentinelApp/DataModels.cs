using Microsoft.ML.Data;
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace DnsSentinelApp
{
    public enum PolicyAction
    { None, Detect, Block }

    public enum ThreatLevel
    { None, Low, Medium, High }

    public class AppConfig
    {
        public int InitialTrainingPeriodDays { get; set; } = 7;
        public int RetrainingPeriodDays { get; set; } = 7;
        public ThreatLevelConfig ThreatLevels { get; set; } = new ThreatLevelConfig();
    }

    public class AppState
    {
        public string CurrentPhase { get; set; } // "Bootstrapping", "Training", "Active"
        public DateTime BootstrapStartTimeUtc { get; set; }
    }

    public class DnsAnomalyPrediction
    {
        [ColumnName("IsAnomaly")] public bool IsAnomaly { get; set; }
        [ColumnName("Score")] public float Score { get; set; }
    }

    public class DnsBehavioralInput
    {
        [JsonIgnore][LoadColumn(0)] public string ClientIP { get; set; }
        [JsonIgnore][LoadColumn(1)] public string Timestamp { get; set; }
        [LoadColumn(2)] public float QueryCount { get; set; }
        [LoadColumn(3)] public float TotalQueryBytes { get; set; }
        [LoadColumn(4)] public float NxdomainRatio { get; set; }
        [LoadColumn(5)] public float ErrorRatio { get; set; }
        [LoadColumn(6)] public float AvgTtl { get; set; }
        [LoadColumn(7)] public float AvgDomainEntropy { get; set; }
        [LoadColumn(8)] public float MaxDomainEntropy { get; set; }
        [LoadColumn(9)] public float DomainRarityScore { get; set; }
        [LoadColumn(10)] public float UniqueTldCount { get; set; }
        [LoadColumn(11)] public float UniqueQtypeRatio { get; set; }
        [LoadColumn(12)] public float AvgRtt { get; set; }
        [LoadColumn(13)] public float ProtocolTcpRatio { get; set; }
        [LoadColumn(14)] public float AvgUdpPayloadSize { get; set; }
        [LoadColumn(15)] public float DnssecOkRatio { get; set; }
        [LoadColumn(16)] public float NumericRatio { get; set; }
        [LoadColumn(17)] public float NonAlphanumericRatio { get; set; }
        [LoadColumn(18)] public float AvgAnswerSize { get; set; }
        [LoadColumn(19)] public float MaxCnameChainLength { get; set; }
        [LoadColumn(20)] public float AvgQueryIat { get; set; }
        [LoadColumn(21)] public float StdevQueryIat { get; set; }
    }

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

    // --- ML Model Schema ---
    // --- Alerting and IOC Models ---
    public class Ioc
    {
        public Ioc(string type, string value)
        { Type = type; Value = value; }

        [JsonPropertyName("type")] public string Type { get; }
        [JsonPropertyName("value")] public string Value { get; }
    }

    public class Policy
    {
        public PolicyAction Action { get; set; }
        public int ScoreThreshold { get; set; }
    }

    public class ThreatLevelConfig
    {
        public Policy High { get; set; } = new Policy { ScoreThreshold = 85, Action = PolicyAction.Block };
        public Policy Low { get; set; } = new Policy { ScoreThreshold = 55, Action = PolicyAction.Detect };
        public Policy Medium { get; set; } = new Policy { ScoreThreshold = 70, Action = PolicyAction.Detect };
    }
}