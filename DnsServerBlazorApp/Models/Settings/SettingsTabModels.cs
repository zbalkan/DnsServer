namespace DnsServerBlazorApp.Models.Settings;

public sealed class FeedRow
{
    public bool Enabled { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public bool IsCustom { get; set; }
}

public sealed class BuiltinFeedPreset
{
    public string Name { get; set; } = string.Empty;
    public List<string>? Urls { get; set; }
}

public sealed class BuiltinForwarderPreset
{
    public string Name { get; set; } = string.Empty;
    public string Protocol { get; set; } = "UDP";
    public List<string>? Addresses { get; set; }
}

public sealed class ForwarderRow
{
    public bool Enabled { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public string Protocol { get; set; } = "Udp";
    public int Order { get; set; } = int.MaxValue;
    public bool IsCustom { get; set; }
}
