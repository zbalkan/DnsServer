using DnsSentinelApp.Anomaly;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DnsSentinelApp.Service
{
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
}