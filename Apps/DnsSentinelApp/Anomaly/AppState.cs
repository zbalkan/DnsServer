using System;

namespace DnsSentinelApp.Anomaly
{
    public class AppState
    {
        public AppPhase CurrentPhase { get; set; }
        public DateTime BootstrapStartTimeUtc { get; set; }
    }
}