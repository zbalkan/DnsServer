using DnsSentinelApp.Anomaly;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DnsSentinelApp.Service
{
    /// <summary>
    /// Defines the contract for the data persistence layer, abstracting the database backend.
    /// </summary>
    public interface IRepository
    {
        /// <summary>
        /// Initializes the data store, ensuring it's ready for use.
        /// </summary>
        Task InitializeAsync();

        /// <summary>
        /// Saves a collection of behavioral data points to the data store.
        /// </summary>
        Task SaveBehavioralDataAsync(IEnumerable<DnsBehavioralInput> behavioralData);

        /// <summary>
        /// Retrieves behavioral data from a specified time window for model training.
        /// </summary>
        Task<IEnumerable<DnsBehavioralInput>> GetBehavioralDataForTrainingAsync(TimeSpan timeWindow);

        /// <summary>
        /// Prunes old data from the data store to manage its size.
        /// </summary>
        Task PruneOldDataAsync(TimeSpan retentionPeriod);
    }
}