using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Zones;

// ── Zone list ──────────────────────────────────────────────────────────────

/// <summary>Response from /api/allowed/list and /api/blocked/list (returns string array).</summary>
public sealed class SimpleZoneListResponse
{
    [JsonPropertyName("zones")]
    public List<string> Zones { get; set; } = [];
}

public sealed class ZoneListResponse
{
    [JsonPropertyName("pageNumber")]
    public int PageNumber { get; set; }

    [JsonPropertyName("totalPages")]
    public int TotalPages { get; set; }

    [JsonPropertyName("totalZones")]
    public int TotalZones { get; set; }

    [JsonPropertyName("zones")]
    public List<ZoneInfo> Zones { get; set; } = [];
}

public sealed class ZoneInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;   // Primary | Secondary | Stub | Forwarder | …

    [JsonPropertyName("dnssecStatus")]
    public string DnssecStatus { get; set; } = string.Empty;   // Unsigned | Signed

    [JsonPropertyName("soaSerial")]
    public long? SoaSerial { get; set; }

    [JsonPropertyName("expiry")]
    public DateTime? Expiry { get; set; }

    [JsonPropertyName("isExpired")]
    public bool IsExpired { get; set; }

    [JsonPropertyName("disabled")]
    public bool Disabled { get; set; }

    [JsonPropertyName("lastModified")]
    public DateTime? LastModified { get; set; }

    [JsonPropertyName("catalogZoneName")]
    public string? CatalogZoneName { get; set; }
}

// ── Zone record list ───────────────────────────────────────────────────────

public sealed class ZoneRecordListResponse
{
    [JsonPropertyName("zone")]
    public ZoneEditInfo Zone { get; set; } = new();

    [JsonPropertyName("pageNumber")]
    public int PageNumber { get; set; }

    [JsonPropertyName("totalPages")]
    public int TotalPages { get; set; }

    [JsonPropertyName("totalRecords")]
    public int TotalRecords { get; set; }

    [JsonPropertyName("records")]
    public List<ZoneRecord> Records { get; set; } = [];
}

public sealed class ZoneEditInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("dnssecStatus")]
    public string DnssecStatus { get; set; } = string.Empty;

    [JsonPropertyName("disabled")]
    public bool Disabled { get; set; }

    [JsonPropertyName("expiry")]
    public DateTime? Expiry { get; set; }

    [JsonPropertyName("isExpired")]
    public bool IsExpired { get; set; }

    [JsonPropertyName("catalogZoneName")]
    public string? CatalogZoneName { get; set; }

    [JsonPropertyName("internal")]
    public bool Internal { get; set; }

    [JsonPropertyName("dnssecPrivateKeys")]
    public List<DnssecKey>? DnssecPrivateKeys { get; set; }
}

public sealed class ZoneRecord
{
    [JsonPropertyName("disabled")]
    public bool Disabled { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("ttl")]
    public int Ttl { get; set; }

    // Alias for Ttl to match usage in views
    [JsonIgnore]
    public int TtlValue { get => Ttl; set => Ttl = value; }

    [JsonPropertyName("rData")]
    public ZoneRecordRData RData { get; set; } = new();

    [JsonPropertyName("dnssecRecords")]
    public List<ZoneRecord>? DnssecRecords { get; set; }
}

public sealed class ZoneRecordRData
{
    // Common fields — different record types populate different fields.
    [JsonPropertyName("value")]
    public string? Value { get; set; }

    [JsonPropertyName("priority")]
    public int? Priority { get; set; }

    [JsonPropertyName("weight")]
    public int? Weight { get; set; }

    [JsonPropertyName("port")]
    public int? Port { get; set; }

    // Raw JSON for complex types displayed verbatim
    [JsonExtensionData]
    public Dictionary<string, System.Text.Json.JsonElement>? Extra { get; set; }

    public override string ToString() =>
        Value ?? (Extra?.Count > 0
            ? string.Join(" ", Extra.Values.Select(v => v.ToString()))
            : string.Empty);
}

// ── DNSSEC ────────────────────────────────────────────────────────────────

public sealed class DnssecKey
{
    [JsonPropertyName("keyTag")]
    public int KeyTag { get; set; }

    [JsonPropertyName("keyType")]
    public string KeyType { get; set; } = string.Empty;   // KSK | ZSK

    [JsonIgnore]
    public bool IsKsk => KeyType.Equals("KSK", StringComparison.OrdinalIgnoreCase);

    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = string.Empty;

    [JsonPropertyName("privateKey")]
    public string PrivateKey { get; set; } = string.Empty;

    [JsonPropertyName("state")]
    public string State { get; set; } = string.Empty;

    [JsonIgnore]
    public string KeyState => State;

    [JsonPropertyName("stateChangedOn")]
    public DateTime? StateChangedOn { get; set; }

    [JsonPropertyName("isRetiring")]
    public bool IsRetiring { get; set; }

    [JsonPropertyName("rolloverDays")]
    public int? RolloverDays { get; set; }
}

public sealed class DnssecPropertiesResponse
{
    [JsonPropertyName("isSigned")]
    public bool IsSigned { get; init; }

    [JsonPropertyName("keys")]
    public List<DnssecKey>? Keys { get; init; }
}

public sealed class DsInfoResponse
{
    [JsonPropertyName("dsRecords")]
    public string DsRecords { get; set; } = string.Empty;
}

// ── Catalog / TSIG ────────────────────────────────────────────────────────

public sealed class CatalogZoneListResponse
{
    [JsonPropertyName("zones")]
    public List<string> Zones { get; set; } = [];
}

public sealed class TsigKeyNamesResponse
{
    [JsonPropertyName("tsigKeyNames")]
    public List<string> TsigKeyNames { get; set; } = [];
}

// ── Zone options ──────────────────────────────────────────────────────────

public sealed class ZoneOptions
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("disabled")]
    public bool Disabled { get; set; }

    [JsonPropertyName("zoneTransfer")]
    public string ZoneTransfer { get; set; } = "Deny";

    [JsonPropertyName("zoneTransferNameServers")]
    public List<string>? ZoneTransferNameServers { get; set; }

    [JsonPropertyName("notify")]
    public string Notify { get; set; } = "None";

    [JsonPropertyName("notifyNameServers")]
    public List<string>? NotifyNameServers { get; set; }

    [JsonPropertyName("queryAccess")]
    public string QueryAccess { get; set; } = "Allow";

    [JsonPropertyName("queryAccessNetworkACL")]
    public List<string>? QueryAccessNetworkACL { get; set; }

    [JsonPropertyName("dynamicUpdates")]
    public string DynamicUpdates { get; set; } = "Deny";

    [JsonPropertyName("dynamicUpdateSecurityPolicies")]
    public List<DynamicUpdatePolicy>? DynamicUpdateSecurityPolicies { get; set; }

    // Secondary / Stub specific
    [JsonPropertyName("primaryNameServerAddresses")]
    public List<string>? PrimaryNameServerAddresses { get; set; }

    [JsonPropertyName("zoneTransferProtocol")]
    public string? ZoneTransferProtocol { get; set; }

    [JsonPropertyName("tsigKeyName")]
    public string? TsigKeyName { get; set; }

    [JsonPropertyName("dnssecValidation")]
    public bool DnssecValidation { get; set; }

    [JsonPropertyName("notifyFailed")]
    public bool NotifyFailed { get; set; }
}

public sealed class DynamicUpdatePolicy
{
    [JsonPropertyName("tsigKeyName")]
    public string TsigKeyName { get; set; } = string.Empty;

    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;

    [JsonPropertyName("allowedTypes")]
    public string AllowedTypes { get; set; } = string.Empty;
}

// ── Zone permissions ──────────────────────────────────────────────────────

public sealed class ZonePermissionsResponse
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("users")]
    public List<ZonePermissionEntry> Users { get; set; } = [];

    [JsonPropertyName("groups")]
    public List<ZonePermissionEntry> Groups { get; set; } = [];
}

public sealed class ZonePermissionEntry
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("canView")]
    public bool CanView { get; set; }

    [JsonPropertyName("canModify")]
    public bool CanModify { get; set; }

    [JsonPropertyName("canDelete")]
    public bool CanDelete { get; set; }
}
