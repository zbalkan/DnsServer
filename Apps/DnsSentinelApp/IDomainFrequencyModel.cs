using System.Collections.Generic;
using System.Threading.Tasks;

namespace DnsSentinelApp
{
    public interface IDomainFrequencyModel
    {
        void UpdateFrequencies(IEnumerable<string> domains);

        float GetRarityScore(string domain);

        Task SaveStateAsync();

        Task LoadStateAsync();
    }
}