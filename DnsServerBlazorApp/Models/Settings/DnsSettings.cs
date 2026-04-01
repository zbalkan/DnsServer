using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Settings;

public sealed class DnsSettingsResponse
{
    // ── General ───────────────────────────────────────────────────────
    [JsonPropertyName("dnsServerDomain")]
    public string DnsServerDomain { get; set; } = string.Empty;

    [JsonPropertyName("dnsServerLocalEndPoints")]
    public List<string>? DnsServerLocalEndPoints { get; set; }

    [JsonPropertyName("dnsServerIPv4SourceAddresses")]
    public List<string>? DnsServerIPv4SourceAddresses { get; set; }

    [JsonPropertyName("dnsServerIPv6SourceAddresses")]
    public List<string>? DnsServerIPv6SourceAddresses { get; set; }

    [JsonPropertyName("defaultRecordTtl")]
    public int DefaultRecordTtl { get; set; } = 3600;

    [JsonPropertyName("defaultNsRecordTtl")]
    public int DefaultNsRecordTtl { get; set; } = 3600;

    [JsonPropertyName("defaultSoaRecordTtl")]
    public int DefaultSoaRecordTtl { get; set; } = 900;

    [JsonPropertyName("defaultResponsiblePerson")]
    public string DefaultResponsiblePerson { get; set; } = string.Empty;

    [JsonPropertyName("useSoaSerialDateScheme")]
    public bool UseSoaSerialDateScheme { get; set; }

    [JsonPropertyName("minSoaRefresh")]
    public int MinSoaRefresh { get; set; } = 300;

    [JsonPropertyName("minSoaRetry")]
    public int MinSoaRetry { get; set; } = 300;

    [JsonPropertyName("zoneTransferAllowedNetworks")]
    public List<string>? ZoneTransferAllowedNetworks { get; set; }

    [JsonPropertyName("notifyAllowedNetworks")]
    public List<string>? NotifyAllowedNetworks { get; set; }

    [JsonPropertyName("dnsAppsEnableAutomaticUpdate")]
    public bool DnsAppsEnableAutomaticUpdate { get; set; }

    // ── IPv6 / UDP ────────────────────────────────────────────────────
    [JsonPropertyName("preferIPv6")]
    public bool PreferIPv6 { get; set; }

    [JsonPropertyName("enableUdpSocketPool")]
    public bool EnableUdpSocketPool { get; set; } = true;

    [JsonPropertyName("socketPoolExcludedPorts")]
    public List<string>? SocketPoolExcludedPorts { get; set; }

    [JsonPropertyName("udpPayloadSize")]
    public int UdpPayloadSize { get; set; } = 1232;

    // ── DNSSEC ────────────────────────────────────────────────────────
    [JsonPropertyName("dnssecValidation")]
    public bool DnssecValidation { get; set; }

    // ── EDNS Client Subnet ────────────────────────────────────────────
    [JsonPropertyName("eDnsClientSubnet")]
    public bool EDnsClientSubnet { get; set; }

    [JsonPropertyName("eDnsClientSubnetIPv4PrefixLength")]
    public int EDnsClientSubnetIPv4PrefixLength { get; set; } = 24;

    [JsonPropertyName("eDnsClientSubnetIPv6PrefixLength")]
    public int EDnsClientSubnetIPv6PrefixLength { get; set; } = 56;

    [JsonPropertyName("eDnsClientSubnetIpv4Override")]
    public string? EDnsClientSubnetIpv4Override { get; set; }

    [JsonPropertyName("eDnsClientSubnetIpv6Override")]
    public string? EDnsClientSubnetIpv6Override { get; set; }

    // ── Query rate limiting ───────────────────────────────────────────
    [JsonPropertyName("qpmPrefixLimitsIPv4")]
    public List<QpmPrefixLimit>? QpmPrefixLimitsIPv4 { get; set; }

    [JsonPropertyName("qpmPrefixLimitsIPv6")]
    public List<QpmPrefixLimit>? QpmPrefixLimitsIPv6 { get; set; }

    [JsonPropertyName("qpmLimitSampleMinutes")]
    public int QpmLimitSampleMinutes { get; set; } = 1;

    [JsonPropertyName("qpmLimitUdpTruncationPercentage")]
    public int QpmLimitUdpTruncationPercentage { get; set; } = 0;

    [JsonPropertyName("qpmLimitBypassList")]
    public List<string>? QpmLimitBypassList { get; set; }

    // ── Advanced timeouts ─────────────────────────────────────────────
    [JsonPropertyName("clientTimeout")]
    public int ClientTimeout { get; set; } = 4000;

    [JsonPropertyName("tcpSendTimeout")]
    public int TcpSendTimeout { get; set; } = 60000;

    [JsonPropertyName("tcpReceiveTimeout")]
    public int TcpReceiveTimeout { get; set; } = 60000;

    [JsonPropertyName("quicIdleTimeout")]
    public int QuicIdleTimeout { get; set; } = 60000;

    [JsonPropertyName("quicMaxInboundStreams")]
    public int QuicMaxInboundStreams { get; set; } = 100;

    [JsonPropertyName("listenBacklog")]
    public int ListenBacklog { get; set; } = 100;

    [JsonPropertyName("maxConcurrentResolutionsPerCore")]
    public int MaxConcurrentResolutionsPerCore { get; set; } = 64;

    // ── Web service ───────────────────────────────────────────────────
    [JsonPropertyName("webServiceLocalAddresses")]
    public List<string>? WebServiceLocalAddresses { get; set; }

    [JsonPropertyName("webServiceHttpPort")]
    public int WebServiceHttpPort { get; set; } = 5380;

    [JsonPropertyName("webServiceEnableTls")]
    public bool WebServiceEnableTls { get; set; }

    [JsonPropertyName("webServiceEnableHttp3")]
    public bool WebServiceEnableHttp3 { get; set; }

    [JsonPropertyName("webServiceHttpToTlsRedirect")]
    public bool WebServiceHttpToTlsRedirect { get; set; }

    [JsonPropertyName("webServiceUseSelfSignedTlsCertificate")]
    public bool WebServiceUseSelfSignedTlsCertificate { get; set; }

    [JsonPropertyName("webServiceTlsPort")]
    public int WebServiceTlsPort { get; set; } = 53443;

    [JsonPropertyName("webServiceTlsCertificatePath")]
    public string? WebServiceTlsCertificatePath { get; set; }

    [JsonPropertyName("webServiceTlsCertificatePassword")]
    public string? WebServiceTlsCertificatePassword { get; set; }

    [JsonPropertyName("webServiceRealIpHeader")]
    public string WebServiceRealIpHeader { get; set; } = "X-Real-IP";

    // ── Optional DNS protocols ────────────────────────────────────────
    [JsonPropertyName("enableDnsOverUdpProxy")]
    public bool EnableDnsOverUdpProxy { get; set; }

    [JsonPropertyName("dnsOverUdpProxyPort")]
    public int DnsOverUdpProxyPort { get; set; } = 53;

    [JsonPropertyName("enableDnsOverTcpProxy")]
    public bool EnableDnsOverTcpProxy { get; set; }

    [JsonPropertyName("dnsOverTcpProxyPort")]
    public int DnsOverTcpProxyPort { get; set; } = 53;

    [JsonPropertyName("enableDnsOverHttp")]
    public bool EnableDnsOverHttp { get; set; }

    [JsonPropertyName("dnsOverHttpPort")]
    public int DnsOverHttpPort { get; set; } = 8053;

    [JsonPropertyName("enableDnsOverTls")]
    public bool EnableDnsOverTls { get; set; }

    [JsonPropertyName("dnsOverTlsPort")]
    public int DnsOverTlsPort { get; set; } = 853;

    [JsonPropertyName("enableDnsOverHttps")]
    public bool EnableDnsOverHttps { get; set; }

    [JsonPropertyName("enableDnsOverHttp3")]
    public bool EnableDnsOverHttp3 { get; set; }

    [JsonPropertyName("dnsOverHttpsPort")]
    public int DnsOverHttpsPort { get; set; } = 443;

    [JsonPropertyName("enableDnsOverQuic")]
    public bool EnableDnsOverQuic { get; set; }

    [JsonPropertyName("dnsOverQuicPort")]
    public int DnsOverQuicPort { get; set; } = 853;

    [JsonPropertyName("dnsTlsCertificatePath")]
    public string? DnsTlsCertificatePath { get; set; }

    [JsonPropertyName("dnsTlsCertificatePassword")]
    public string? DnsTlsCertificatePassword { get; set; }

    [JsonPropertyName("reverseProxyNetworkACL")]
    public List<string>? ReverseProxyNetworkACL { get; set; }

    [JsonPropertyName("dnsOverHttpRealIpHeader")]
    public string? DnsOverHttpRealIpHeader { get; set; }

    // ── Forwarders / recursion ────────────────────────────────────────
    [JsonPropertyName("recursion")]
    public string Recursion { get; set; } = "AllowOnlyForPrivateNetworks";

    [JsonPropertyName("recursionNetworkACL")]
    public List<string>? RecursionNetworkACL { get; set; }

    [JsonPropertyName("randomizeName")]
    public bool RandomizeName { get; set; } = true;

    [JsonPropertyName("qnameMinimization")]
    public bool QnameMinimization { get; set; } = true;

    [JsonPropertyName("nsRevalidation")]
    public bool NsRevalidation { get; set; }

    [JsonPropertyName("resolverRetries")]
    public int ResolverRetries { get; set; } = 2;

    [JsonPropertyName("resolverTimeout")]
    public int ResolverTimeout { get; set; } = 2000;

    [JsonPropertyName("resolverMaxStackCount")]
    public int ResolverMaxStackCount { get; set; } = 16;

    [JsonPropertyName("forwarders")]
    public List<string>? Forwarders { get; set; }

    [JsonPropertyName("forwarderProtocol")]
    public string ForwarderProtocol { get; set; } = "Udp";

    [JsonPropertyName("enableConcurrentForwarding")]
    public bool EnableConcurrentForwarding { get; set; }

    [JsonPropertyName("forwarderConcurrency")]
    public int ForwarderConcurrency { get; set; } = 2;

    [JsonPropertyName("forwarderRetries")]
    public int ForwarderRetries { get; set; } = 3;

    [JsonPropertyName("forwarderTimeout")]
    public int ForwarderTimeout { get; set; } = 2000;

    // ── Blocking ──────────────────────────────────────────────────────
    [JsonPropertyName("enableBlocking")]
    public bool EnableBlocking { get; set; }

    [JsonPropertyName("allowTxtBlockingReport")]
    public bool AllowTxtBlockingReport { get; set; }

    [JsonPropertyName("blockingType")]
    public string BlockingType { get; set; } = "NxDomain";

    [JsonPropertyName("customBlockingAddresses")]
    public List<string>? CustomBlockingAddresses { get; set; }

    [JsonPropertyName("blockListUrls")]
    public List<string>? BlockListUrls { get; set; }

    [JsonPropertyName("blockListUpdateIntervalHours")]
    public int BlockListUpdateIntervalHours { get; set; } = 24;

    [JsonPropertyName("blockListNextUpdatedOn")]
    public DateTime? BlockListNextUpdatedOn { get; set; }

    // ── Proxy ─────────────────────────────────────────────────────────
    [JsonPropertyName("proxy")]
    public ProxySettings? Proxy { get; set; }

    // ── Caching ───────────────────────────────────────────────────────
    [JsonPropertyName("serveStale")]
    public bool ServeStale { get; set; }

    [JsonPropertyName("serveStaleTtl")]
    public int ServeStaleTtl { get; set; } = 259200;

    [JsonPropertyName("serveStaleAnswerTtl")]
    public int ServeStaleAnswerTtl { get; set; } = 30;

    [JsonPropertyName("serveStaleResetTtl")]
    public bool ServeStaleResetTtl { get; set; }

    [JsonPropertyName("serveStaleMaxWaitTime")]
    public int ServeStaleMaxWaitTime { get; set; } = 10000;

    [JsonPropertyName("cacheMaximumEntries")]
    public int CacheMaximumEntries { get; set; } = 10000;

    [JsonPropertyName("cacheMinimumRecordTtl")]
    public int CacheMinimumRecordTtl { get; set; } = 10;

    [JsonPropertyName("cacheMaximumRecordTtl")]
    public int CacheMaximumRecordTtl { get; set; } = 3600;

    [JsonPropertyName("cacheNegativeRecordTtl")]
    public int CacheNegativeRecordTtl { get; set; } = 300;

    [JsonPropertyName("cacheFailureRecordTtl")]
    public int CacheFailureRecordTtl { get; set; } = 10;

    [JsonPropertyName("cachePrefetchEligibility")]
    public int CachePrefetchEligibility { get; set; } = 2;

    [JsonPropertyName("cachePrefetchTrigger")]
    public int CachePrefetchTrigger { get; set; } = 9;

    [JsonPropertyName("cachePrefetchSampleIntervalInMinutes")]
    public int CachePrefetchSampleIntervalInMinutes { get; set; } = 5;

    [JsonPropertyName("cachePrefetchSampleEligibilityHitsPerHour")]
    public int CachePrefetchSampleEligibilityHitsPerHour { get; set; } = 30;

    // ── Logging ───────────────────────────────────────────────────────
    [JsonPropertyName("loggingType")]
    public string LoggingType { get; set; } = "File";

    [JsonPropertyName("logFolder")]
    public string LogFolder { get; set; } = "logs";

    [JsonPropertyName("maxLogFileDays")]
    public int MaxLogFileDays { get; set; } = 0;

    [JsonPropertyName("logQueries")]
    public bool LogQueries { get; set; }

    [JsonPropertyName("ignoreResolverLogs")]
    public bool IgnoreResolverLogs { get; set; }

    [JsonPropertyName("useLocalTime")]
    public bool UseLocalTime { get; set; }

    // ── TSIG keys ─────────────────────────────────────────────────────
    [JsonPropertyName("tsigKeys")]
    public List<TsigKeyEntry>? TsigKeys { get; set; }

    // ── Cluster nodes (refreshed alongside settings) ──────────────────
    [JsonPropertyName("clusterNodes")]
    public List<Models.Auth.ClusterNodeRef>? ClusterNodes { get; set; }
}

public sealed class QpmPrefixLimit
{
    [JsonPropertyName("prefix")]
    public string Prefix { get; set; } = string.Empty;

    [JsonPropertyName("udpLimit")]
    public int UdpLimit { get; set; }

    [JsonPropertyName("tcpLimit")]
    public int TcpLimit { get; set; }
}

public sealed class ProxySettings
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "None";   // None | Http | Socks5

    [JsonPropertyName("address")]
    public string Address { get; set; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; set; } = 8080;

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }

    [JsonPropertyName("bypass")]
    public List<string>? Bypass { get; set; }
}

public sealed class TsigKeyEntry
{
    [JsonPropertyName("keyName")]
    public string KeyName { get; set; } = string.Empty;

    [JsonPropertyName("sharedSecret")]
    public string SharedSecret { get; set; } = string.Empty;

    [JsonPropertyName("algorithmName")]
    public string AlgorithmName { get; set; } = "hmac-sha256";
}
