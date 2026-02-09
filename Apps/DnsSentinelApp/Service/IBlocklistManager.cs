using DnsSentinelApp.Anomaly;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DnsSentinelApp.Service
{
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