using DnsServerBlazorApp.Models.Zones;

namespace DnsServerBlazorApp.Services;

public sealed class SimpleZoneListService(ApiService api)
{
    public Task<ApiResult<SimpleZoneListResponse>> LoadZonesAsync(string zoneType, string node)
        => api.GetAsync<SimpleZoneListResponse>($"api/{NormalizeZoneType(zoneType)}/list?node={Uri.EscapeDataString(node)}");

    public Task<ApiResult<ZoneRecordListResponse>> LoadZoneRecordsAsync(string zone, string node)
        => api.GetAsync<ZoneRecordListResponse>(
            $"api/zones/records/get?zone={Uri.EscapeDataString(zone)}&node={Uri.EscapeDataString(node)}");

    public Task<ApiResult<object>> AddZoneAsync(string zoneType, string node, string zone)
        => api.PostAsync<object>($"api/{NormalizeZoneType(zoneType)}/add", new Dictionary<string, string>
        {
            ["domain"] = zone,
            ["node"] = node,
        });

    public Task<ApiResult<object>> DeleteZoneAsync(string zoneType, string node, string zone)
        => api.PostAsync<object>($"api/{NormalizeZoneType(zoneType)}/delete", new Dictionary<string, string>
        {
            ["domain"] = zone,
            ["node"] = node,
        });

    public string BuildExportUrl(string zoneType, string node)
        => api.BuildDownloadUrl($"api/{NormalizeZoneType(zoneType)}/export?node={Uri.EscapeDataString(node)}");

    private static string NormalizeZoneType(string zoneType)
        => string.Equals(zoneType, "blocked", StringComparison.OrdinalIgnoreCase)
            ? "blocked"
            : "allowed";
}
