using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsSentinelApp.Anomaly
{
    public class ThreatClassifier
    {
        private readonly List<PolicyDefinition> _policies;

        public ThreatClassifier(ThreatLevelConfig threatLevels)
        {
            _policies = new List<PolicyDefinition>
        {
            new PolicyDefinition { Level = ThreatLevel.High, ScoreThreshold = threatLevels.High.ScoreThreshold, Action = threatLevels.High.Action },
            new PolicyDefinition { Level = ThreatLevel.Medium, ScoreThreshold = threatLevels.Medium.ScoreThreshold, Action = threatLevels.Medium.Action },
            new PolicyDefinition { Level = ThreatLevel.Low, ScoreThreshold = threatLevels.Low.ScoreThreshold, Action = threatLevels.Low.Action }
        }.OrderByDescending(p => p.ScoreThreshold).ToList();
        }

        public DnsThreatAlert Classify(DnsAnomalyPrediction prediction, DnsBehavioralInput input, Dictionary<string, IEnumerable<string>> evidence)
        {
            int numericalScore = CalculateNumericalThreatScore(prediction, input);
            PolicyDefinition triggeredPolicy = _policies.FirstOrDefault(p => numericalScore >= p.ScoreThreshold);

            if (triggeredPolicy == null)
            {
                return null;
            }

            List<Ioc> iocs = new List<Ioc> { new Ioc("ip-src", input.ClientIP) };
            List<string> justifications = new List<string>();
            string suspectedAttackType = "General Anomalous Behavior";

            if (input.AvgDomainEntropy > 4.2)
            {
                suspectedAttackType = "Suspected DNS Tunneling / DGA";
                justifications.Add($"unusually high domain entropy ({input.AvgDomainEntropy:F2})");
                if (evidence.TryGetValue("TopHighEntropyDomains", out IEnumerable<string> domains))
                {
                    iocs.AddRange(domains.Select(d => new Ioc("domain", d)));
                }
            }
            if (input.NxdomainRatio > 0.6)
            {
                if (suspectedAttackType == "General Anomalous Behavior")
                    suspectedAttackType = "Suspected Network Scanning";
                justifications.Add($"excessive NXDOMAIN rate ({input.NxdomainRatio:P0})");
                if (evidence.TryGetValue("TopNxDomains", out IEnumerable<string> domains))
                {
                    iocs.AddRange(domains.Select(d => new Ioc("domain|nx", d)));
                }
            }

            return new DnsThreatAlert
            {
                SuspectedAttackType = suspectedAttackType,
                ThreatLevel = triggeredPolicy.Level,
                ThreatScore = numericalScore,
                Justification = "Anomaly detected due to " + string.Join(", and ", justifications) + ".",
                Iocs = iocs,
                ActionTaken = triggeredPolicy.Action
            };
        }

        private int CalculateNumericalThreatScore(DnsAnomalyPrediction prediction, DnsBehavioralInput input)
        {
            const float ML_SCORE_WEIGHT = 50.0f;
            const float SENSITIVITY = 2.0f;

            double normalizedMlScore = 1.0 / (1.0 + Math.Exp(-prediction.Score * SENSITIVITY));
            double threatScore = normalizedMlScore * ML_SCORE_WEIGHT;

            if (input.NxdomainRatio > 0.5) threatScore += 20;
            if (input.AvgDomainEntropy > 4.0) threatScore += 15;

            return Math.Min(100, (int)Math.Round(threatScore));
        }

        private class PolicyDefinition
        {
            public ThreatLevel Level { get; set; }
            public int ScoreThreshold { get; set; }
            public PolicyAction Action { get; set; }
        }
    }

    public class ClientProfile
    {
        private long _queryCount;
        private long _totalQueryBytes;
        private long _nxdomainCount;
        private long _errorCount;
        private readonly List<double> _ttlValues = new List<double>();
        private readonly List<double> _entropyValues = new List<double>();
        private readonly HashSet<string> _uniqueTlds = new HashSet<string>();
        private readonly HashSet<DnsResourceRecordType> _uniqueQtypes = new HashSet<DnsResourceRecordType>();
        private readonly List<double> _rttValues = new List<double>();
        private long _tcpQueryCount;
        private readonly List<double> _udpPayloadSizes = new List<double>();
        private long _dnssecOkCount;
        private readonly List<double> _numericRatios = new List<double>();
        private readonly List<double> _nonAlphanumericRatios = new List<double>();
        private readonly List<double> _answerSizes = new List<double>();
        private int _maxCnameChainLength;
        private readonly List<DateTime> _queryTimestamps = new List<DateTime>();
        private readonly ConcurrentQueue<string> _highEntropyDomainSamples = new ConcurrentQueue<string>();
        private readonly ConcurrentQueue<string> _nxDomainSamples = new ConcurrentQueue<string>();

        public void Update(DnsDatagram datagram, IPEndPoint remoteEP)
        {
            lock (this)
            {
                _queryTimestamps.Add(DateTime.UtcNow);
                Interlocked.Increment(ref _queryCount);

                if (datagram.Metadata != null)
                {
                    Interlocked.Add(ref _totalQueryBytes, datagram.Metadata.DatagramSize);
                    _rttValues.Add(datagram.Metadata.RoundTripTime);
                    if (datagram.Metadata.Protocol == DnsTransportProtocol.Tcp)
                    {
                        Interlocked.Increment(ref _tcpQueryCount);
                    }
                }

                if (datagram.IsResponse)
                {
                    if (datagram.RCODE == DnsResponseCode.NxDomain)
                    {
                        Interlocked.Increment(ref _nxdomainCount);
                        if (_nxDomainSamples.Count < 10) _nxDomainSamples.Enqueue(datagram.Question[0].Name);
                    }
                    else if (datagram.RCODE != DnsResponseCode.NoError)
                    {
                        Interlocked.Increment(ref _errorCount);
                    }

                    int currentCnameChain = 0;
                    foreach (var record in datagram.Answer)
                    {
                        _ttlValues.Add(record.TTL);
                        _answerSizes.Add(record.RDATA.UncompressedLength);

                        if (record.Type == DnsResourceRecordType.CNAME)
                        {
                            currentCnameChain++;
                        }
                        else
                        {
                            if (currentCnameChain > _maxCnameChainLength)
                            {
                                _maxCnameChainLength = currentCnameChain;
                            }
                            currentCnameChain = 0;
                        }
                    }
                    if (currentCnameChain > _maxCnameChainLength)
                    {
                        _maxCnameChainLength = currentCnameChain;
                    }
                }
                else
                {
                    var question = datagram.Question[0];
                    var qName = question.Name;

                    double entropy = DnsUtils.CalculateEntropy(qName);
                    _entropyValues.Add(entropy);
                    if (entropy > 4.2 && _highEntropyDomainSamples.Count < 10)
                    {
                        _highEntropyDomainSamples.Enqueue(qName);
                    }

                    _numericRatios.Add(DnsUtils.CalculateNumericRatio(qName));
                    _nonAlphanumericRatios.Add(DnsUtils.CalculateNonAlphanumericRatio(qName));

                    var tld = DnsUtils.GetTld(qName);
                    if (tld != null) _uniqueTlds.Add(tld);

                    _uniqueQtypes.Add(question.Type);

                    if (datagram.EDNS != null)
                    {
                        _udpPayloadSizes.Add(datagram.EDNS.UdpPayloadSize);
                        if (datagram.EDNS.Flags.HasFlag(EDnsHeaderFlags.DNSSEC_OK))
                        {
                            Interlocked.Increment(ref _dnssecOkCount);
                        }
                    }
                }
            }
        }

        public DnsBehavioralInput CreateBehavioralSnapshot(string clientIp)
        {
            lock (this)
            {
                var iatStats = DnsUtils.CalculateIatStats(_queryTimestamps);

                return new DnsBehavioralInput
                {
                    ClientIP = clientIp,
                    Timestamp = DateTime.UtcNow.ToString("o"),
                    QueryCount = _queryCount,
                    TotalQueryBytes = _totalQueryBytes,
                    NxdomainRatio = _queryCount > 0 ? (float)_nxdomainCount / _queryCount : 0,
                    ErrorRatio = _queryCount > 0 ? (float)_errorCount / _queryCount : 0,
                    AvgTtl = _ttlValues.Count != 0 ? (float)_ttlValues.Average() : 0,
                    AvgDomainEntropy = _entropyValues.Count != 0 ? (float)_entropyValues.Average() : 0,
                    MaxDomainEntropy = _entropyValues.Count != 0 ? (float)_entropyValues.Max() : 0,
                    DomainRarityScore = 0, // Placeholder
                    UniqueTldCount = _uniqueTlds.Count,
                    UniqueQtypeRatio = _queryCount > 0 ? (float)_uniqueQtypes.Count / _queryCount : 0,
                    AvgRtt = _rttValues.Count != 0 ? (float)_rttValues.Average() : 0,
                    ProtocolTcpRatio = _queryCount > 0 ? (float)_tcpQueryCount / _queryCount : 0,
                    AvgUdpPayloadSize = _udpPayloadSizes.Count != 0 ? (float)_udpPayloadSizes.Average() : 0,
                    DnssecOkRatio = _queryCount > 0 ? (float)_dnssecOkCount / _queryCount : 0,
                    NumericRatio = _numericRatios.Count != 0 ? (float)_numericRatios.Average() : 0,
                    NonAlphanumericRatio = _nonAlphanumericRatios.Count != 0 ? (float)_nonAlphanumericRatios.Average() : 0,
                    AvgAnswerSize = _answerSizes.Count != 0 ? (float)_answerSizes.Average() : 0,
                    MaxCnameChainLength = _maxCnameChainLength,
                    AvgQueryIat = (float)iatStats.Average,
                    StdevQueryIat = (float)iatStats.StdDev
                };
            }
        }

        public Dictionary<string, IEnumerable<string>> GetIocEvidence()
        {
            lock (this)
            {
                return new Dictionary<string, IEnumerable<string>>
            {
                { "TopHighEntropyDomains", _highEntropyDomainSamples.Take(5).ToList() },
                { "TopNxDomains", _nxDomainSamples.Take(5).ToList() }
            };
            }
        }
    }
}