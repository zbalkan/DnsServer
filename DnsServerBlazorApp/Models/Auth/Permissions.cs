using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Auth;

/// <summary>
/// Per-section permission set returned inside the session info.
/// Mirrors sessionData.info.permissions from the original JS.
/// </summary>
public sealed class Permissions
{
    [JsonPropertyName("Dashboard")]
    public SectionPermission Dashboard { get; set; } = new();

    [JsonPropertyName("Zones")]
    public SectionPermission Zones { get; set; } = new();

    [JsonPropertyName("Cache")]
    public SectionPermission Cache { get; set; } = new();

    [JsonPropertyName("Allowed")]
    public SectionPermission Allowed { get; set; } = new();

    [JsonPropertyName("Blocked")]
    public SectionPermission Blocked { get; set; } = new();

    [JsonPropertyName("Apps")]
    public SectionPermission Apps { get; set; } = new();

    [JsonPropertyName("DnsClient")]
    public SectionPermission DnsClient { get; set; } = new();

    [JsonPropertyName("Settings")]
    public SectionPermission Settings { get; set; } = new();

    [JsonPropertyName("DhcpServer")]
    public SectionPermission DhcpServer { get; set; } = new();

    [JsonPropertyName("Administration")]
    public SectionPermission Administration { get; set; } = new();

    [JsonPropertyName("Logs")]
    public SectionPermission Logs { get; set; } = new();
}

public sealed class SectionPermission
{
    [JsonPropertyName("canView")]
    public bool CanView { get; set; }

    [JsonPropertyName("canModify")]
    public bool CanModify { get; set; }

    [JsonPropertyName("canDelete")]
    public bool CanDelete { get; set; }
}

/// <summary>Per-section permission entry returned by api/admin/permissions/list.</summary>
public sealed class PermissionEntry
{
    [JsonPropertyName("section")]
    public string Section { get; set; } = string.Empty;

    [JsonPropertyName("permissions")]
    public List<PermissionDetail> Permissions { get; set; } = [];
}

public sealed class PermissionDetail
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;   // "User" | "Group"

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("canView")]
    public bool CanView { get; set; }

    [JsonPropertyName("canModify")]
    public bool CanModify { get; set; }

    [JsonPropertyName("canDelete")]
    public bool CanDelete { get; set; }
}
