using Microsoft.ML.Data;
using System.Text.Json.Serialization;

namespace DnsSentinelApp.Anomaly
{
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
}