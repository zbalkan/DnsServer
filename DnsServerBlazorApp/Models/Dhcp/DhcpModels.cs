using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Dhcp;

public sealed class DhcpLeasesResponse
{
    [JsonPropertyName("leases")]
    public List<DhcpLease> Leases { get; set; } = [];
}

public sealed class DhcpLease
{
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;

    [JsonPropertyName("clientIdentifier")]
    public string ClientIdentifier { get; set; } = string.Empty;

    [JsonPropertyName("hardwareAddress")]
    public string HardwareAddress { get; set; } = string.Empty;

    [JsonPropertyName("address")]
    public string Address { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;   // Dynamic | Reserved

    [JsonPropertyName("hostName")]
    public string HostName { get; set; } = string.Empty;

    [JsonPropertyName("leaseObtained")]
    public DateTime LeaseObtained { get; set; }

    [JsonPropertyName("leaseExpires")]
    public DateTime LeaseExpires { get; set; }
}

public sealed class DhcpScopesResponse
{
    [JsonPropertyName("scopes")]
    public List<DhcpScope> Scopes { get; set; } = [];
}

public sealed class DhcpScope
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("startingAddress")]
    public string StartingAddress { get; set; } = string.Empty;

    [JsonPropertyName("endingAddress")]
    public string EndingAddress { get; set; } = string.Empty;

    [JsonPropertyName("subnetMask")]
    public string SubnetMask { get; set; } = string.Empty;

    [JsonPropertyName("leaseTimeDays")]
    public int LeaseTimeDays { get; set; } = 1;

    [JsonPropertyName("leaseTimeHours")]
    public int LeaseTimeHours { get; set; }

    [JsonPropertyName("leaseTimeMinutes")]
    public int LeaseTimeMinutes { get; set; }

    [JsonPropertyName("offerDelayTime")]
    public int OfferDelayTime { get; set; }

    [JsonPropertyName("pingCheckEnabled")]
    public bool PingCheckEnabled { get; set; }

    [JsonPropertyName("pingCheckTimeout")]
    public int PingCheckTimeout { get; set; } = 1000;

    [JsonPropertyName("pingCheckRetries")]
    public int PingCheckRetries { get; set; } = 2;

    [JsonPropertyName("domainName")]
    public string? DomainName { get; set; }

    [JsonPropertyName("domainSearchList")]
    public List<string>? DomainSearchList { get; set; }

    [JsonPropertyName("dnsUpdates")]
    public bool DnsUpdates { get; set; }

    [JsonPropertyName("dnsOverwriteForDynamicLease")]
    public bool DnsOverwriteForDynamicLease { get; set; }

    [JsonPropertyName("dnsTtl")]
    public int DnsTtl { get; set; } = 900;

    [JsonPropertyName("serverAddress")]
    public string? ServerAddress { get; set; }

    [JsonPropertyName("serverHostName")]
    public string? ServerHostName { get; set; }

    [JsonPropertyName("bootFileName")]
    public string? BootFileName { get; set; }

    [JsonPropertyName("nextServerAddress")]
    public string? NextServerAddress { get; set; }

    [JsonPropertyName("router")]
    public string? Router { get; set; }

    [JsonPropertyName("routerListedAsNameServer")]
    public bool RouterListedAsNameServer { get; set; }

    [JsonPropertyName("useThisDnsServer")]
    public bool UseThisDnsServer { get; set; }

    [JsonPropertyName("dnsServers")]
    public List<string>? DnsServers { get; set; }

    [JsonPropertyName("winsServers")]
    public List<string>? WinsServers { get; set; }

    [JsonPropertyName("ntpServers")]
    public List<string>? NtpServers { get; set; }

    [JsonPropertyName("ntpServerDomainNames")]
    public List<string>? NtpServerDomainNames { get; set; }

    [JsonPropertyName("staticRoutes")]
    public List<DhcpStaticRoute>? StaticRoutes { get; set; }

    [JsonPropertyName("vendorInfo")]
    public List<DhcpVendorInfo>? VendorInfo { get; set; }

    [JsonPropertyName("capwapAcIpAddresses")]
    public List<string>? CapwapAcIpAddresses { get; set; }

    [JsonPropertyName("genericOptions")]
    public List<DhcpGenericOption>? GenericOptions { get; set; }

    [JsonPropertyName("exclusions")]
    public List<DhcpExclusion>? Exclusions { get; set; }

    [JsonPropertyName("reservedLeases")]
    public List<DhcpReservedLease>? ReservedLeases { get; set; }

    [JsonPropertyName("allowOnlyReservedLeases")]
    public bool AllowOnlyReservedLeases { get; set; }

    [JsonPropertyName("blockLocallyAdministeredMacAddresses")]
    public bool BlockLocallyAdministeredMacAddresses { get; set; }

    [JsonPropertyName("ignoreClientIdentifierOption")]
    public bool IgnoreClientIdentifierOption { get; set; }
}

public sealed class DhcpStaticRoute
{
    [JsonPropertyName("destination")]
    public string Destination { get; set; } = string.Empty;

    [JsonPropertyName("subnetMask")]
    public string SubnetMask { get; set; } = string.Empty;

    [JsonPropertyName("router")]
    public string Router { get; set; } = string.Empty;
}

public sealed class DhcpVendorInfo
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty;

    [JsonPropertyName("information")]
    public string Information { get; set; } = string.Empty;
}

public sealed class DhcpGenericOption
{
    [JsonPropertyName("code")]
    public int Code { get; set; }

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;
}

public sealed class DhcpExclusion
{
    [JsonPropertyName("startingAddress")]
    public string StartingAddress { get; set; } = string.Empty;

    [JsonPropertyName("endingAddress")]
    public string EndingAddress { get; set; } = string.Empty;
}

public sealed class DhcpReservedLease
{
    [JsonPropertyName("hardwareAddress")]
    public string HardwareAddress { get; set; } = string.Empty;

    [JsonPropertyName("address")]
    public string Address { get; set; } = string.Empty;

    [JsonPropertyName("hostName")]
    public string? HostName { get; set; }

    [JsonPropertyName("comments")]
    public string? Comments { get; set; }
}
