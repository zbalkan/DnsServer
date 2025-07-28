using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DnsSentinelApp
{
    /// <summary>
    /// Defines the contract for the data persistence layer, abstracting the database backend.
    /// </summary>
    public interface IRepository : IDisposable
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

    /// <summary>
    /// Defines the contract for the machine learning service, abstracting the ML framework and algorithm.
    /// </summary>
    public interface IAnomalyDetectionService : IDisposable
    {
        /// <summary>
        /// Trains a new anomaly detection model using the provided behavioral data.
        /// The implementation is responsible for saving the trained model to a persistent location.
        /// </summary>
        Task TrainModelAsync(IEnumerable<DnsBehavioralInput> trainingData);

        /// <summary>
        /// Loads a pre-trained model from a persistent location into memory.
        /// </summary>
        /// <returns>True if a model was loaded successfully, otherwise false.</returns>
        bool LoadModel();

        /// <summary>
        /// Analyzes a behavioral data point and returns a prediction.
        /// </summary>
        /// <returns>A DnsAnomalyPrediction object containing the model's output.</returns>
        DnsAnomalyPrediction Predict(DnsBehavioralInput behavioralData);
    }

    /// <summary>
    /// Defines the contract for managing the IOC blocklist.
    /// </summary>
    public interface IBlocklistManager
    {
        /// <summary>
        /// Loads the blocklist from persistent storage into a high-performance, in-memory set.
        /// </summary>
        Task LoadBlocklistAsync();

        /// <summary>
        /// Adds new IOCs to the blocklist and persists the changes.
        /// </summary>
        Task AddToBlocklistAsync(IEnumerable<Ioc> iocs);

        /// <summary>
        /// Checks if a given domain is present in the in-memory blocklist.
        /// This method must be extremely fast.
        /// </summary>
        bool IsDomainBlocked(string domain, out string foundMatch);

        /// <summary>
        /// Checks if a given IP address is present in the in-memory blocklist.
        /// </summary>
        bool IsIpBlocked(string ip);
    }
}