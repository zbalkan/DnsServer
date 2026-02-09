using DnsSentinelApp.Anomaly;
using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DnsSentinelApp.Service
{
    public sealed class SqliteRepository : IRepository
    {
        private readonly string _connectionString;

        public SqliteRepository(string databasePath)
        {
            _connectionString = $"Data Source={databasePath}";
        }

        public async Task InitializeAsync()
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = @"
            CREATE TABLE IF NOT EXISTS BehavioralData (
                Id INTEGER PRIMARY KEY, Timestamp TEXT NOT NULL, ClientIP TEXT NOT NULL,
                QueryCount REAL NOT NULL, TotalQueryBytes REAL NOT NULL, NxdomainRatio REAL NOT NULL,
                ErrorRatio REAL NOT NULL, AvgTtl REAL NOT NULL, AvgDomainEntropy REAL NOT NULL,
                MaxDomainEntropy REAL NOT NULL, DomainRarityScore REAL NOT NULL, UniqueTldCount REAL NOT NULL,
                UniqueQtypeRatio REAL NOT NULL, AvgRtt REAL NOT NULL, ProtocolTcpRatio REAL NOT NULL,
                AvgUdpPayloadSize REAL NOT NULL, DnssecOkRatio REAL NOT NULL,
                -- New Feature Columns
                NumericRatio REAL NOT NULL, NonAlphanumericRatio REAL NOT NULL, AvgAnswerSize REAL NOT NULL,
                MaxCnameChainLength REAL NOT NULL, AvgQueryIat REAL NOT NULL, StdevQueryIat REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_BehavioralData_Timestamp ON BehavioralData (Timestamp);
        ";
            await command.ExecuteNonQueryAsync();
        }

        public async Task SaveBehavioralDataAsync(IEnumerable<DnsBehavioralInput> behavioralData)
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();
            using var transaction = connection.BeginTransaction();

            var command = connection.CreateCommand();
            command.CommandText = @"
            INSERT INTO BehavioralData (
                Timestamp, ClientIP, QueryCount, TotalQueryBytes, NxdomainRatio, ErrorRatio, AvgTtl,
                AvgDomainEntropy, MaxDomainEntropy, DomainRarityScore, UniqueTldCount, UniqueQtypeRatio,
                AvgRtt, ProtocolTcpRatio, AvgUdpPayloadSize, DnssecOkRatio, NumericRatio,
                NonAlphanumericRatio, AvgAnswerSize, MaxCnameChainLength, AvgQueryIat, StdevQueryIat
            ) VALUES (
                $timestamp, $clientIp, $queryCount, $totalQueryBytes, $nxdomainRatio, $errorRatio, $avgTtl,
                $avgDomainEntropy, $maxDomainEntropy, $domainRarityScore, $uniqueTldCount, $uniqueQtypeRatio,
                $avgRtt, $protocolTcpRatio, $avgUdpPayloadSize, $dnssecOkRatio, $numericRatio,
                $nonAlphanumericRatio, $avgAnswerSize, $maxCnameChainLength, $avgQueryIat, $stdevQueryIat
            );
        ";

            foreach (var dataPoint in behavioralData)
            {
                command.Parameters.Clear();
                command.Parameters.AddWithValue("$timestamp", dataPoint.Timestamp);
                command.Parameters.AddWithValue("$clientIp", dataPoint.ClientIP);
                command.Parameters.AddWithValue("$queryCount", dataPoint.QueryCount);
                command.Parameters.AddWithValue("$totalQueryBytes", dataPoint.TotalQueryBytes);
                command.Parameters.AddWithValue("$nxdomainRatio", dataPoint.NxdomainRatio);
                command.Parameters.AddWithValue("$errorRatio", dataPoint.ErrorRatio);
                command.Parameters.AddWithValue("$avgTtl", dataPoint.AvgTtl);
                command.Parameters.AddWithValue("$avgDomainEntropy", dataPoint.AvgDomainEntropy);
                command.Parameters.AddWithValue("$maxDomainEntropy", dataPoint.MaxDomainEntropy);
                command.Parameters.AddWithValue("$domainRarityScore", dataPoint.DomainRarityScore);
                command.Parameters.AddWithValue("$uniqueTldCount", dataPoint.UniqueTldCount);
                command.Parameters.AddWithValue("$uniqueQtypeRatio", dataPoint.UniqueQtypeRatio);
                command.Parameters.AddWithValue("$avgRtt", dataPoint.AvgRtt);
                command.Parameters.AddWithValue("$protocolTcpRatio", dataPoint.ProtocolTcpRatio);
                command.Parameters.AddWithValue("$avgUdpPayloadSize", dataPoint.AvgUdpPayloadSize);
                command.Parameters.AddWithValue("$dnssecOkRatio", dataPoint.DnssecOkRatio);
                command.Parameters.AddWithValue("$numericRatio", dataPoint.NumericRatio);
                command.Parameters.AddWithValue("$nonAlphanumericRatio", dataPoint.NonAlphanumericRatio);
                command.Parameters.AddWithValue("$avgAnswerSize", dataPoint.AvgAnswerSize);
                command.Parameters.AddWithValue("$maxCnameChainLength", dataPoint.MaxCnameChainLength);
                command.Parameters.AddWithValue("$avgQueryIat", dataPoint.AvgQueryIat);
                command.Parameters.AddWithValue("$stdevQueryIat", dataPoint.StdevQueryIat);
                await command.ExecuteNonQueryAsync();
            }
            await transaction.CommitAsync();
        }

        public async Task<IEnumerable<DnsBehavioralInput>> GetBehavioralDataForTrainingAsync(TimeSpan timeWindow)
        {
            var data = new List<DnsBehavioralInput>();
            var sinceTimestamp = DateTime.UtcNow.Subtract(timeWindow).ToString("o");

            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = @"
            SELECT ClientIP, Timestamp, QueryCount, TotalQueryBytes, NxdomainRatio, ErrorRatio, AvgTtl,
                   AvgDomainEntropy, MaxDomainEntropy, DomainRarityScore, UniqueTldCount, UniqueQtypeRatio,
                   AvgRtt, ProtocolTcpRatio, AvgUdpPayloadSize, DnssecOkRatio, NumericRatio,
                   NonAlphanumericRatio, AvgAnswerSize, MaxCnameChainLength, AvgQueryIat, StdevQueryIat
            FROM BehavioralData
            WHERE Timestamp >= $sinceTimestamp;
        ";
            command.Parameters.AddWithValue("$sinceTimestamp", sinceTimestamp);

            using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                data.Add(new DnsBehavioralInput
                {
                    ClientIP = reader.GetString(0),
                    Timestamp = reader.GetString(1),
                    QueryCount = reader.GetFloat(2),
                    TotalQueryBytes = reader.GetFloat(3),
                    NxdomainRatio = reader.GetFloat(4),
                    ErrorRatio = reader.GetFloat(5),
                    AvgTtl = reader.GetFloat(6),
                    AvgDomainEntropy = reader.GetFloat(7),
                    MaxDomainEntropy = reader.GetFloat(8),
                    DomainRarityScore = reader.GetFloat(9),
                    UniqueTldCount = reader.GetFloat(10),
                    UniqueQtypeRatio = reader.GetFloat(11),
                    AvgRtt = reader.GetFloat(12),
                    ProtocolTcpRatio = reader.GetFloat(13),
                    AvgUdpPayloadSize = reader.GetFloat(14),
                    DnssecOkRatio = reader.GetFloat(15),
                    NumericRatio = reader.GetFloat(16),
                    NonAlphanumericRatio = reader.GetFloat(17),
                    AvgAnswerSize = reader.GetFloat(18),
                    MaxCnameChainLength = reader.GetFloat(19),
                    AvgQueryIat = reader.GetFloat(20),
                    StdevQueryIat = reader.GetFloat(21)
                });
            }
            return data;
        }

        public async Task PruneOldDataAsync(TimeSpan retentionPeriod)
        {
            var beforeTimestamp = DateTime.UtcNow.Subtract(retentionPeriod).ToString("o");
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM BehavioralData WHERE Timestamp < $beforeTimestamp;";
            command.Parameters.AddWithValue("$beforeTimestamp", beforeTimestamp);
            await command.ExecuteNonQueryAsync();
        }
    }
}