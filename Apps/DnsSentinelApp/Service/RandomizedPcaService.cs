using DnsSentinelApp.Anomaly;
using Microsoft.ML;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace DnsSentinelApp.Service
{
    public sealed class RandomizedPcaService : IAnomalyDetectionService
    {
        private readonly MLContext _mlContext;
        private readonly string _modelPath;
        private ITransformer _trainedModel;
        private PredictionEngine<DnsBehavioralInput, DnsAnomalyPrediction> _predictionEngine;

        public RandomizedPcaService(string modelPath)
        {
            _mlContext = new MLContext(seed: 0);
            _modelPath = modelPath;
        }

        public bool LoadModel()
        {
            if (!File.Exists(_modelPath)) return false;
            try
            {
                _trainedModel = _mlContext.Model.Load(_modelPath, out _);
                _predictionEngine = _mlContext.Model.CreatePredictionEngine<DnsBehavioralInput, DnsAnomalyPrediction>(_trainedModel);
                return true;
            }
            catch (Exception)
            {
                _trainedModel = null;
                _predictionEngine = null;
                return false;
            }
        }

        public DnsAnomalyPrediction Predict(DnsBehavioralInput behavioralData)
        {
            if (_predictionEngine == null)
            {
                return new DnsAnomalyPrediction { IsAnomaly = false, Score = 0.0f };
            }
            return _predictionEngine.Predict(behavioralData);
        }

        public async Task TrainModelAsync(IEnumerable<DnsBehavioralInput> trainingData)
        {
            if (!trainingData.Any())
            {
                throw new InvalidOperationException("Cannot train model with no data.");
            }

            IDataView trainingDataView = _mlContext.Data.LoadFromEnumerable(trainingData);

            var featureNames = new[] {
            nameof(DnsBehavioralInput.QueryCount), nameof(DnsBehavioralInput.TotalQueryBytes),
            nameof(DnsBehavioralInput.NxdomainRatio), nameof(DnsBehavioralInput.ErrorRatio),
            nameof(DnsBehavioralInput.AvgTtl), nameof(DnsBehavioralInput.AvgDomainEntropy),
            nameof(DnsBehavioralInput.MaxDomainEntropy), nameof(DnsBehavioralInput.DomainRarityScore),
            nameof(DnsBehavioralInput.UniqueTldCount), nameof(DnsBehavioralInput.UniqueQtypeRatio),
            nameof(DnsBehavioralInput.AvgRtt), nameof(DnsBehavioralInput.ProtocolTcpRatio),
            nameof(DnsBehavioralInput.AvgUdpPayloadSize), nameof(DnsBehavioralInput.DnssecOkRatio),
            nameof(DnsBehavioralInput.NumericRatio), nameof(DnsBehavioralInput.NonAlphanumericRatio),
            nameof(DnsBehavioralInput.AvgAnswerSize), nameof(DnsBehavioralInput.MaxCnameChainLength),
            nameof(DnsBehavioralInput.AvgQueryIat), nameof(DnsBehavioralInput.StdevQueryIat)
        };

            // The correct pipeline for RandomizedPca anomaly detection.
            // It requires features to be concatenated and then normalized.
            var pipeline = _mlContext.Transforms.Concatenate("Features", featureNames)
                .Append(_mlContext.Transforms.NormalizeMinMax("Features", "Features"))
                .Append(_mlContext.AnomalyDetection.Trainers.RandomizedPca(
                    featureColumnName: "Features",
                    rank: 10, // The number of principal components to find. A good starting point.
                    oversampling: 5, // Helps find the principal components more accurately.
                    ensureZeroMean: true));

            var newModel = pipeline.Fit(trainingDataView);

            string tempModelPath = _modelPath + ".tmp";
            _mlContext.Model.Save(newModel, trainingDataView.Schema, tempModelPath);
            File.Move(tempModelPath, _modelPath, true);

            // After saving, immediately reload the new model into the active prediction engine.
            LoadModel();

            await Task.CompletedTask;
        }

        public void Dispose()
        {
            _predictionEngine?.Dispose();
        }
    }
}