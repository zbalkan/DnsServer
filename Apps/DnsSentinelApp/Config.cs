using DnsSentinelApp.Anomaly;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace DnsSentinelApp
{
    /// <summary>
    /// Configuration settings for the DNS Sentinel application.
    /// </summary>
    public class Config
    {
        /// <summary>
        /// Number of days for the initial training period (must be > 0).
        /// </summary>
        [JsonPropertyName("initialTrainingPeriodDays")]
        [Range(1, int.MaxValue, ErrorMessage = "InitialTrainingPeriodDays must be greater than zero.")]
        public int InitialTrainingPeriodDays { get; set; } = 7;

        /// <summary>
        /// Number of days between retraining cycles (must be > 0).
        /// </summary>
        [JsonPropertyName("retrainingPeriodDays")]
        [Range(1, int.MaxValue, ErrorMessage = "RetrainingPeriodDays must be greater than zero.")]
        public int RetrainingPeriodDays { get; set; } = 7;

        /// <summary>
        /// Threat level thresholds and corresponding actions.
        /// </summary>
        [JsonPropertyName("threatLevels")]
        [Required(ErrorMessage = "ThreatLevels configuration is required.")]
        public ThreatLevelConfig ThreatLevels { get; set; } = new ThreatLevelConfig();

        /// <summary>
        /// Validates configuration values based on DataAnnotations attributes.
        /// Throws a ValidationException on failure.
        /// </summary>
        public void Validate()
        {
            var context = new ValidationContext(this);
            // Validate this object and all nested properties
            Validator.ValidateObject(this, context, validateAllProperties: true);
        }
    }
}