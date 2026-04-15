using DnsServerBlazorApp.Models.Apps;
using System.Text.Json;

namespace DnsServerBlazorApp.Helpers;

public static class DisplayFormatHelper
{
    public static string FormatUptime(DateTime? uptimestamp)
    {
        if (uptimestamp is null)
            return "—";

        var ts = DateTime.UtcNow - uptimestamp.Value;
        if (ts.TotalDays >= 1)
            return $"{(int)ts.TotalDays}d {ts.Hours}h {ts.Minutes}m";

        if (ts.TotalHours >= 1)
            return $"{ts.Hours}h {ts.Minutes}m {ts.Seconds}s";

        return $"{ts.Minutes}m {ts.Seconds}s";
    }

    public static string FormatRData(JsonElement? rdata)
    {
        if (rdata is null)
            return string.Empty;

        return rdata.Value.ValueKind switch
        {
            JsonValueKind.Object => string.Join(" ", rdata.Value.EnumerateObject().Select(p => p.Value.ToString())),
            JsonValueKind.String => rdata.Value.GetString() ?? string.Empty,
            _ => rdata.Value.ToString()
        };
    }

    public static string BuildAppClassTooltip(DnsAppClass cls)
    {
        List<string> features = [];
        if (cls.IsRequestController) features.Add("Request Controller");
        if (cls.IsRequestBlockingHandler) features.Add("Blocking Handler");
        if (cls.IsAuthoritativeRequestHandler) features.Add("Authoritative");
        if (cls.IsQueryLogger) features.Add("Query Logger");
        if (cls.IsPostProcessor) features.Add("Post Processor");

        return features.Count > 0
            ? string.Join(", ", features)
            : cls.ClassPath.ToShortClassName();
    }
}
