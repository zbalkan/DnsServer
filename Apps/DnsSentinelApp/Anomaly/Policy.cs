namespace DnsSentinelApp.Anomaly
{
    public class Policy
    {
        public PolicyAction Action { get; set; }
        public int ScoreThreshold { get; set; }
    }
}