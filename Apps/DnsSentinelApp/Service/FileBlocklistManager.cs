using DnsSentinelApp.Anomaly;
using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DnsSentinelApp.Service
{
    public sealed class FileBlocklistManager : IBlocklistManager
    {
        private readonly string _domainBlocklistPath;
        private readonly string _ipBlocklistPath;
        private FrozenSet<string> _domainBlocklist = FrozenSet<string>.Empty;
        private FrozenSet<string> _ipBlocklist = FrozenSet<string>.Empty;
        private readonly SemaphoreSlim _fileLock = new SemaphoreSlim(1, 1);

        public FileBlocklistManager(string appFolder)
        {
            _domainBlocklistPath = Path.Combine(appFolder, "blocklist_domains.txt");
            _ipBlocklistPath = Path.Combine(appFolder, "blocklist_ips.txt");
        }

        public async Task LoadBlocklistAsync()
        {
            await _fileLock.WaitAsync();
            try
            {
                HashSet<string> domains = File.Exists(_domainBlocklistPath)
                    ? (await File.ReadAllLinesAsync(_domainBlocklistPath)).ToHashSet(StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                HashSet<string> ips = File.Exists(_ipBlocklistPath)
                    ? (await File.ReadAllLinesAsync(_ipBlocklistPath)).ToHashSet(StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                _domainBlocklist = domains.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
                _ipBlocklist = ips.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
            }
            finally
            {
                _fileLock.Release();
            }
        }

        public async Task AddToBlocklistAsync(IEnumerable<Ioc> iocs)
        {
            HashSet<string> newDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> newIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Ioc ioc in iocs)
            {
                if (ioc.Type == "domain" || ioc.Type == "domain|nx")
                {
                    newDomains.Add(ioc.Value);
                }
                else if (ioc.Type == "ip-src")
                {
                    newIps.Add(ioc.Value);
                }
            }

            if (newDomains.Count == 0 && newIps.Count == 0) return;

            await _fileLock.WaitAsync();
            try
            {
                if (newDomains.Count != 0)
                {
                    HashSet<string> currentDomains = _domainBlocklist.ToHashSet(StringComparer.OrdinalIgnoreCase);
                    int originalCount = currentDomains.Count;
                    currentDomains.UnionWith(newDomains);
                    if (currentDomains.Count > originalCount)
                    {
                        await File.WriteAllLinesAsync(_domainBlocklistPath, currentDomains);
                        _domainBlocklist = currentDomains.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
                    }
                }

                if (newIps.Count != 0)
                {
                    HashSet<string> currentIps = _ipBlocklist.ToHashSet(StringComparer.OrdinalIgnoreCase);
                    int originalCount = currentIps.Count;
                    currentIps.UnionWith(newIps);
                    if (currentIps.Count > originalCount)
                    {
                        await File.WriteAllLinesAsync(_ipBlocklistPath, currentIps);
                        _ipBlocklist = currentIps.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
                    }
                }
            }
            finally
            {
                _fileLock.Release();
            }
        }

        public bool IsDomainBlocked(string domain, out string foundMatch)
        {
            FrozenSet<string> currentBlocklist = _domainBlocklist;
            ReadOnlySpan<char> currentSpan = domain.AsSpan();

            while (true)
            {
                string key = new string(currentSpan);
                if (currentBlocklist.Contains(key))
                {
                    foundMatch = key;
                    return true;
                }

                int dotIndex = currentSpan.IndexOf('.');
                if (dotIndex == -1) break;

                currentSpan = currentSpan.Slice(dotIndex + 1);
            }

            foundMatch = null;
            return false;
        }

        public bool IsIpBlocked(string ip)
        {
            return _ipBlocklist.Contains(ip);
        }
    }
}