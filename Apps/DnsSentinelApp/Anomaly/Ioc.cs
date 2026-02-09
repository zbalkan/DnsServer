using System.Text.Json.Serialization;

namespace DnsSentinelApp.Anomaly
{
    // --- ML Model Schema ---
    // --- Alerting and IOC Models ---
    public class Ioc
    {
        public Ioc(string type, string value)
        { Type = type; Value = value; }

        [JsonPropertyName("type")] public string Type { get; }
        [JsonPropertyName("value")] public string Value { get; }
    }
}