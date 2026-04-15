namespace DnsServerBlazorApp.Infrastructure.Storage;

public interface IClientStateStore
{
    ValueTask SetAsync<T>(string key, T value);
    ValueTask<T?> GetAsync<T>(string key);
    ValueTask RemoveAsync(string key);
}
