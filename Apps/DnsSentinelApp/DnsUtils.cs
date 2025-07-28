using System;
using System.Collections.Generic;
using System.Linq;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsSentinelApp
{
    public static class DnsUtils
    {
        public static double CalculateEntropy(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return 0;
            }

            Dictionary<char, int> characterCounts = text.GroupBy(c => c)
                                      .ToDictionary(g => g.Key, g => g.Count());

            double entropy = characterCounts.Values.Sum(count =>
            {
                double probability = (double)count / text.Length;
                return -probability * Math.Log(probability, 2);
            });

            return entropy;
        }

        public static string GetTld(string domain)
        {
            if (string.IsNullOrEmpty(domain)) return null;
            int lastDot = domain.LastIndexOf('.');
            if (lastDot == -1 || lastDot == domain.Length - 1) return null;
            return domain.Substring(lastDot + 1);
        }

        public static double CalculateNumericRatio(string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            double numericCount = text.Count(char.IsDigit);
            return numericCount / text.Length;
        }

        public static double CalculateNonAlphanumericRatio(string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            double nonAlphanumCount = text.Count(c => !char.IsLetterOrDigit(c));
            return nonAlphanumCount / text.Length;
        }

        public struct IatStat
        {
            public double Average { get; set; }
            public double StdDev { get; set; }

            public IatStat()
            {
                Average = 0;
                StdDev = 0;
            }
        }

        public static IatStat CalculateIatStats(List<DateTime> timestamps)
        {
            if (timestamps.Count < 2) return default;

            var iatMilliseconds = new List<double>();
            for (int i = 1; i < timestamps.Count; i++)
            {
                iatMilliseconds.Add((timestamps[i] - timestamps[i - 1]).TotalMilliseconds);
            }

            if (iatMilliseconds.Count == 0) return default;

            double avg = iatMilliseconds.Average();
            double sumOfSquares = iatMilliseconds.Sum(val => (val - avg) * (val - avg));
            double stdDev = Math.Sqrt(sumOfSquares / iatMilliseconds.Count);

            return new IatStat { Average = avg, StdDev = stdDev };
        }

        public static DnsDatagram CreateRefusedResponse(DnsDatagram request)
        {
            return new DnsDatagram(
                ID: request.Identifier, isResponse: true, OPCODE: request.OPCODE,
                authoritativeAnswer: false, truncation: false, recursionDesired: request.RecursionDesired,
                recursionAvailable: true, authenticData: false, checkingDisabled: request.CheckingDisabled,
                RCODE: DnsResponseCode.Refused, question: request.Question,
                answer: Array.Empty<DnsResourceRecord>(), authority: Array.Empty<DnsResourceRecord>(),
                additional: Array.Empty<DnsResourceRecord>()
            );
        }

        public static DnsDatagram CreateNxDomainResponse(DnsDatagram request, string domain)
        {
            var soa = new DnsSOARecordData(domain, "hostmaster." + domain, 1, 7200, 3600, 1209600, 3600);
            var authority = new[] { new DnsResourceRecord(domain, DnsResourceRecordType.SOA, DnsClass.IN, 60, soa) };
            return new DnsDatagram(
                ID: request.Identifier, isResponse: true, OPCODE: request.OPCODE,
                authoritativeAnswer: true, truncation: false, recursionDesired: request.RecursionDesired,
                recursionAvailable: true, authenticData: false, checkingDisabled: request.CheckingDisabled,
                RCODE: DnsResponseCode.NxDomain, question: request.Question,
                answer: Array.Empty<DnsResourceRecord>(), authority: authority,
                additional: Array.Empty<DnsResourceRecord>()
            );
        }
    }
}