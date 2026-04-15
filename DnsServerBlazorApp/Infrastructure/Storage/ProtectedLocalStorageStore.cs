using System.Security.Cryptography;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace DnsServerBlazorApp.Infrastructure.Storage;

public sealed class ProtectedLocalStorageStore(ProtectedLocalStorage storage)
    : IClientStateStore
{
    public async ValueTask SetAsync<T>(string key, T value)
    {
        try
        {
            await storage.SetAsync(key, value);
        }
        catch (InvalidOperationException)
        {
        }
    }

    public async ValueTask<T?> GetAsync<T>(string key)
    {
        try
        {
            var result = await storage.GetAsync<T>(key);
            return result.Success ? result.Value : default;
        }
        catch (CryptographicException)
        {
            return default;
        }
        catch (InvalidOperationException)
        {
            return default;
        }
    }

    public async ValueTask RemoveAsync(string key)
    {
        try
        {
            await storage.DeleteAsync(key);
        }
        catch (InvalidOperationException)
        {
        }
    }
}
