namespace DnsSentinelApp.Anomaly
{
    public class ThreatLevelConfig
    {
        public Policy High { get; set; } = new Policy { ScoreThreshold = 85, Action = PolicyAction.Block };
        public Policy Low { get; set; } = new Policy { ScoreThreshold = 55, Action = PolicyAction.Detect };
        public Policy Medium { get; set; } = new Policy { ScoreThreshold = 70, Action = PolicyAction.Detect };
    }
}