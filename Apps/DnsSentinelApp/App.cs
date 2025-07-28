/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 20245 Zafer Balkan (zafer@zaferbalkan.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using DnsSentinelApp.Anomaly;
using DnsSentinelApp.Service;
using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsSentinelApp
{
    public sealed class App : IDnsApplication
    {
        #region variables

        IDnsServer _dnsServer;
        Config _config;
        AppState _appState;
        string _stateFilePath;

        // --- Services ---
        IRepository _repository;

        IAnomalyDetectionService _mlService;
        IBlocklistManager _blocklistManager;
        ThreatClassifier _threatClassifier;

        // --- Real-Time State ---
        ConcurrentDictionary<IPAddress, ClientProfile> _activeProfiles;

        CancellationTokenSource _appShutdownCts;

        readonly JsonSerializerOptions _jsonSerializerOptions = new JsonSerializerOptions() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

        #endregion variables

        #region public

        public string Description => "A real-time DNS anomaly detection engine with a permanent blocking policy.";

        public async Task InitializeAsync(IDnsServer dnsServer, string configJson)
        {
            _dnsServer = dnsServer;

            _config = ParseConfig(configJson);

            _activeProfiles = new ConcurrentDictionary<IPAddress, ClientProfile>();

            string appFolder = _dnsServer.ApplicationFolder;
            Directory.CreateDirectory(appFolder);
            _stateFilePath = Path.Combine(appFolder, "sentinel_state.json");
            await LoadOrInitializeStateAsync();

            // --- Initialize Services ---
            _repository = new SqliteRepository(Path.Combine(appFolder, "sentinel_data.db"));
            await _repository.InitializeAsync();

            _mlService = new RandomizedPcaService(Path.Combine(appFolder, "dns_anomaly_model.zip"));
            _mlService.LoadModel();

            _blocklistManager = new FileBlocklistManager(appFolder);
            await _blocklistManager.LoadBlocklistAsync();

            _threatClassifier = new ThreatClassifier(_config.ThreatLevels);

            // --- Start Background Planes ---
            _appShutdownCts = new CancellationTokenSource();
            if (_appState.CurrentPhase == AppPhase.Active)
            {
                // If we are already active, start all planes immediately.
                _ = StartAnalysisPlaneAsync(_appShutdownCts.Token);
                _ = StartTrainingPlaneAsync(_appShutdownCts.Token);
            }
            else
            {
                // If bootstrapping, only start the main lifecycle loop which will handle the transition.
                _ = StartLifecycleManagerAsync(_appShutdownCts.Token);
            }

            _dnsServer.WriteLog("DnsSentinelApp: Initialization complete. All three operational planes are active.");
        }

        private Config ParseConfig(string configJson)
        {
            Config cfg = JsonSerializer.Deserialize<Config>(configJson, _jsonSerializerOptions)
                     ?? throw new InvalidOperationException("Failed to deserialize configuration.");
            try
            {
                cfg.Validate();
            }
            catch (ValidationException vex)
            {
                _dnsServer.WriteLog($"Configuration error: {vex.Message}");
                throw;
            }
            return cfg;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            // =================================================================
            // --- ENFORCEMENT PLANE (High-Speed, Low-Latency) ---
            // =================================================================

            // The logic is now simpler: it only checks the persistent blocklist.
            if (_blocklistManager.IsIpBlocked(remoteEP.Address.ToString()))
            {
                return Task.FromResult(DnsUtils.CreateRefusedResponse(request));
            }

            if (_blocklistManager.IsDomainBlocked(request.Question[0].Name, out string foundMatch))
            {
                return Task.FromResult(DnsUtils.CreateNxDomainResponse(request, foundMatch));
            }

            if (!request.IsResponse)
            {
                ClientProfile clientProfile = _activeProfiles.GetOrAdd(remoteEP.Address, _ => new ClientProfile());
                clientProfile.Update(request, remoteEP);
            }

            return Task.FromResult<DnsDatagram>(null);
        }
        #endregion public

        #region IDisposable

        public void Dispose()
        {
            _appShutdownCts?.Cancel();
            _appShutdownCts?.Dispose();
            _mlService?.Dispose();
        }
        #endregion IDisposable

        #region private

        // The implementation of the background planes (StartAnalysisPlaneAsync, StartTrainingPlaneAsync)
        // and the core logic methods (CollectAndAnalyzeProfilesAsync, RetrainModelAsync)
        // remains exactly the same as the previous version. The only change is that when
        // a `Block` action is triggered, the IOCs are added to the persistent blocklist
        // with no expiration time.

        private async Task StartAnalysisPlaneAsync(CancellationToken cancellationToken)
        {
            using PeriodicTimer timer = new PeriodicTimer(TimeSpan.FromMinutes(5));
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                try
                {
                    await CollectAndAnalyzeProfilesAsync();
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog($"ERROR: The Analysis Plane encountered an unhandled exception. Error: {ex.Message}");
                }
            }
        }

        private async Task StartTrainingPlaneAsync(CancellationToken cancellationToken)
        {
            using PeriodicTimer timer = new PeriodicTimer(TimeSpan.FromDays(_config.RetrainingPeriodDays));
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                try
                {
                    await RetrainModelAsync();
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog($"ERROR: The Training Plane encountered an unhandled exception. Error: {ex.Message}");
                }
            }
        }

        private async Task LoadOrInitializeStateAsync()
        {
            if (File.Exists(_stateFilePath))
            {
                string json = await File.ReadAllTextAsync(_stateFilePath);
                _appState = JsonSerializer.Deserialize<AppState>(json);
            }
            else
            {
                _appState = new AppState
                {
                    CurrentPhase = AppPhase.Bootstrapping,
                    BootstrapStartTimeUtc = DateTime.UtcNow
                };
                await SaveStateAsync();
            }
        }

        private Task SaveStateAsync()
        {
            string json = JsonSerializer.Serialize(_appState, _jsonSerializerOptions);
            return File.WriteAllTextAsync(_stateFilePath, json);
        }

        private async Task StartLifecycleManagerAsync(CancellationToken cancellationToken)
        {
            // This loop manages the transition from Bootstrapping -> Training -> Active
            while (!cancellationToken.IsCancellationRequested)
            {
                if (_appState.CurrentPhase == AppPhase.Bootstrapping)
                {
                    TimeSpan elapsedTime = DateTime.UtcNow - _appState.BootstrapStartTimeUtc;
                    if (elapsedTime >= TimeSpan.FromDays(_config.InitialTrainingPeriodDays))
                    {
                        _dnsServer.WriteLog("DnsSentinelApp: Initial training period complete. Transitioning to Training phase.");
                        _appState.CurrentPhase = AppPhase.Training;
                        await SaveStateAsync();

                        // Trigger the first training immediately
                        await RetrainModelAsync();

                        // Now transition to Active
                        _dnsServer.WriteLog("DnsSentinelApp: Initial training complete. Transitioning to Active phase.");
                        _appState.CurrentPhase = AppPhase.Active;
                        await SaveStateAsync();

                        // Start the normal operational planes and exit this manager.
                        _ = StartAnalysisPlaneAsync(cancellationToken);
                        _ = StartTrainingPlaneAsync(cancellationToken);
                        return; // Exit the lifecycle manager loop.
                    }
                }

                // Check every hour if the bootstrap period is over.
                await Task.Delay(TimeSpan.FromHours(1), cancellationToken);
            }
        }

        private async Task CollectAndAnalyzeProfilesAsync()
        {
            ConcurrentDictionary<IPAddress, ClientProfile> profilesToProcess = Interlocked.Exchange(ref _activeProfiles, new ConcurrentDictionary<IPAddress, ClientProfile>());
            if (profilesToProcess.IsEmpty) return;

            List<DnsBehavioralInput> behavioralDataList = new List<DnsBehavioralInput>();
            foreach (KeyValuePair<IPAddress, ClientProfile> kvp in profilesToProcess)
            {
                DnsBehavioralInput behavioralData = kvp.Value.CreateBehavioralSnapshot(kvp.Key.ToString());
                if (behavioralData.QueryCount < 10) continue;

                behavioralDataList.Add(behavioralData);

                DnsAnomalyPrediction prediction = _mlService.Predict(behavioralData);
                if (prediction.IsAnomaly)
                {
                    DnsThreatAlert alert = _threatClassifier.Classify(prediction, behavioralData, kvp.Value.GetIocEvidence());
                    if (alert != null)
                    {
                        string alertJson = JsonSerializer.Serialize(alert, _jsonSerializerOptions);
                        _dnsServer.WriteLog(alertJson);

                        if (alert.ActionTaken == PolicyAction.Block)
                        {
                            await _blocklistManager.AddToBlocklistAsync(alert.Iocs);
                        }
                    }
                }
            }

            if (behavioralDataList.Count != 0)
            {
                await _repository.SaveBehavioralDataAsync(behavioralDataList);
            }
        }

        private async Task RetrainModelAsync()
        {
            _dnsServer.WriteLog("DnsSentinelApp: Training Plane initiated model renewal cycle...");

            IEnumerable<DnsBehavioralInput> trainingData = await _repository.GetBehavioralDataForTrainingAsync(TimeSpan.FromDays(14));
            if (trainingData.Count() < 100)
            {
                _dnsServer.WriteLog("WARNING: Insufficient data for model retraining. Skipping this cycle.");
                return;
            }

            await _mlService.TrainModelAsync(trainingData);
            await _repository.PruneOldDataAsync(TimeSpan.FromDays(30));

            _dnsServer.WriteLog("DnsSentinelApp: Training Plane cycle complete. A new model has been deployed.");
        }

        #endregion private
    }
}