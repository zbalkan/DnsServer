using DnsServerBlazorApp.Models.Settings;

namespace DnsServerBlazorApp.Helpers;

public static class SettingsTabHelper
{
    public static string NormalizeForwarderProtocol(string? protocol) => protocol?.ToUpperInvariant() switch
    {
        "UDP" => "Udp",
        "TCP" => "Tcp",
        "TLS" => "Tls",
        "HTTPS" => "Https",
        "QUIC" => "Quic",
        _ => "Udp"
    };

    public static string GuessFeedTitle(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return uri.Host;

        return url;
    }

    public static string ListToLines(List<string>? list) =>
        list is null ? "" : string.Join("\n", list);

    public static List<string>? LinesToList(string text)
    {
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return lines.Length == 0 ? null : [.. lines];
    }

    public static string ListToLinesInt(List<int>? list) =>
        list is null ? "" : string.Join("\n", list);

    public static List<int>? LinesToIntList(string text)
    {
        List<int> values = [];
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var line in lines)
        {
            if (int.TryParse(line, out var value))
                values.Add(value);
        }

        return values.Count == 0 ? null : values;
    }

    public static Dictionary<string, string> BuildForm(DnsSettingsResponse s)
    {
        var f = new Dictionary<string, string>();
        void Str(string k, string? v) { if (v is not null) f[k] = v; }
        void Int(string k, int v) { f[k] = v.ToString(); }
        void Bool(string k, bool v) { f[k] = v ? "true" : "false"; }
        void Lines(string k, List<string>? v) { f[k] = v?.Count > 0 ? string.Join(",", v) : string.Empty; }
        void LinesInt(string k, List<int>? v) { f[k] = v?.Count > 0 ? string.Join(",", v) : string.Empty; }

        Str("dnsServerDomain", s.DnsServerDomain);
        Lines("dnsServerLocalEndPoints", s.DnsServerLocalEndPoints);
        Lines("dnsServerIPv4SourceAddresses", s.DnsServerIPv4SourceAddresses);
        Lines("dnsServerIPv6SourceAddresses", s.DnsServerIPv6SourceAddresses);
        Int("defaultRecordTtl", s.DefaultRecordTtl);
        Int("defaultNsRecordTtl", s.DefaultNsRecordTtl);
        Int("defaultSoaRecordTtl", s.DefaultSoaRecordTtl);
        Str("defaultResponsiblePerson", s.DefaultResponsiblePerson);
        Bool("useSoaSerialDateScheme", s.UseSoaSerialDateScheme);
        Int("minSoaRefresh", s.MinSoaRefresh);
        Int("minSoaRetry", s.MinSoaRetry);
        Lines("zoneTransferAllowedNetworks", s.ZoneTransferAllowedNetworks);
        Lines("notifyAllowedNetworks", s.NotifyAllowedNetworks);
        Bool("dnsAppsEnableAutomaticUpdate", s.DnsAppsEnableAutomaticUpdate);

        Bool("preferIPv6", s.PreferIPv6);
        Bool("enableUdpSocketPool", s.EnableUdpSocketPool);
        LinesInt("socketPoolExcludedPorts", s.SocketPoolExcludedPorts);
        Int("udpPayloadSize", s.UdpPayloadSize);
        Bool("dnssecValidation", s.DnssecValidation);

        Bool("eDnsClientSubnet", s.EDnsClientSubnet);
        Int("eDnsClientSubnetIPv4PrefixLength", s.EDnsClientSubnetIPv4PrefixLength);
        Int("eDnsClientSubnetIPv6PrefixLength", s.EDnsClientSubnetIPv6PrefixLength);
        Str("eDnsClientSubnetIpv4Override", s.EDnsClientSubnetIpv4Override);
        Str("eDnsClientSubnetIpv6Override", s.EDnsClientSubnetIpv6Override);

        Int("clientTimeout", s.ClientTimeout);
        Int("tcpSendTimeout", s.TcpSendTimeout);
        Int("tcpReceiveTimeout", s.TcpReceiveTimeout);
        Int("quicIdleTimeout", s.QuicIdleTimeout);
        Int("quicMaxInboundStreams", s.QuicMaxInboundStreams);
        Int("listenBacklog", s.ListenBacklog);
        Int("maxConcurrentResolutionsPerCore", s.MaxConcurrentResolutionsPerCore);

        Lines("webServiceLocalAddresses", s.WebServiceLocalAddresses);
        Int("webServiceHttpPort", s.WebServiceHttpPort);
        Bool("webServiceEnableTls", s.WebServiceEnableTls);
        Bool("webServiceEnableHttp3", s.WebServiceEnableHttp3);
        Bool("webServiceHttpToTlsRedirect", s.WebServiceHttpToTlsRedirect);
        Bool("webServiceUseSelfSignedTlsCertificate", s.WebServiceUseSelfSignedTlsCertificate);
        Int("webServiceTlsPort", s.WebServiceTlsPort);
        Str("webServiceTlsCertificatePath", s.WebServiceTlsCertificatePath);
        Str("webServiceTlsCertificatePassword", s.WebServiceTlsCertificatePassword);
        Str("webServiceRealIpHeader", s.WebServiceRealIpHeader);

        Bool("enableDnsOverUdpProxy", s.EnableDnsOverUdpProxy);
        Int("dnsOverUdpProxyPort", s.DnsOverUdpProxyPort);
        Bool("enableDnsOverTcpProxy", s.EnableDnsOverTcpProxy);
        Int("dnsOverTcpProxyPort", s.DnsOverTcpProxyPort);
        Bool("enableDnsOverHttp", s.EnableDnsOverHttp);
        Int("dnsOverHttpPort", s.DnsOverHttpPort);
        Bool("enableDnsOverTls", s.EnableDnsOverTls);
        Int("dnsOverTlsPort", s.DnsOverTlsPort);
        Bool("enableDnsOverHttps", s.EnableDnsOverHttps);
        Bool("enableDnsOverHttp3", s.EnableDnsOverHttp3);
        Int("dnsOverHttpsPort", s.DnsOverHttpsPort);
        Bool("enableDnsOverQuic", s.EnableDnsOverQuic);
        Int("dnsOverQuicPort", s.DnsOverQuicPort);
        Str("dnsTlsCertificatePath", s.DnsTlsCertificatePath);
        Str("dnsTlsCertificatePassword", s.DnsTlsCertificatePassword);
        Lines("reverseProxyNetworkACL", s.ReverseProxyNetworkACL);
        Str("dnsOverHttpRealIpHeader", s.DnsOverHttpRealIpHeader);

        Str("forwarderProtocol", s.ForwarderProtocol);
        Lines("forwarders", s.Forwarders);
        Bool("concurrentForwarding", s.ConcurrentForwarding);
        Int("forwarderConcurrency", s.ForwarderConcurrency);
        Int("forwarderRetries", s.ForwarderRetries);
        Int("forwarderTimeout", s.ForwarderTimeout);

        Str("recursion", s.Recursion);
        Lines("recursionNetworkACL", s.RecursionNetworkACL);
        Bool("qnameMinimization", s.QnameMinimization);
        Bool("randomizeName", s.RandomizeName);
        Bool("nsRevalidation", s.NsRevalidation);
        Int("resolverRetries", s.ResolverRetries);
        Int("resolverTimeout", s.ResolverTimeout);
        Int("resolverMaxStackCount", s.ResolverMaxStackCount);

        Bool("enableBlocking", s.EnableBlocking);
        Bool("allowTxtBlockingReport", s.AllowTxtBlockingReport);
        Str("blockingType", s.BlockingType);
        Lines("customBlockingAddresses", s.CustomBlockingAddresses);
        Lines("blockListUrls", s.BlockListUrls);
        Int("blockListUpdateIntervalHours", s.BlockListUpdateIntervalHours);

        Bool("serveStale", s.ServeStale);
        Int("serveStaleTtl", s.ServeStaleTtl);
        Int("serveStaleAnswerTtl", s.ServeStaleAnswerTtl);
        Int("serveStaleResetTtl", s.ServeStaleResetTtl);
        Int("serveStaleMaxWaitTime", s.ServeStaleMaxWaitTime);
        Int("cacheMaximumEntries", s.CacheMaximumEntries);
        Int("cacheMinimumRecordTtl", s.CacheMinimumRecordTtl);
        Int("cacheMaximumRecordTtl", s.CacheMaximumRecordTtl);
        Int("cacheNegativeRecordTtl", s.CacheNegativeRecordTtl);
        Int("cacheFailureRecordTtl", s.CacheFailureRecordTtl);
        Int("cachePrefetchEligibility", s.CachePrefetchEligibility);
        Int("cachePrefetchTrigger", s.CachePrefetchTrigger);
        Int("cachePrefetchSampleIntervalInMinutes", s.CachePrefetchSampleIntervalInMinutes);
        Int("cachePrefetchSampleEligibilityHitsPerHour", s.CachePrefetchSampleEligibilityHitsPerHour);

        Str("loggingType", s.LoggingType);
        Str("logFolder", s.LogFolder);
        Int("maxLogFileDays", s.MaxLogFileDays);
        Bool("logQueries", s.LogQueries);
        Bool("ignoreResolverLogs", s.IgnoreResolverLogs);
        Bool("useLocalTime", s.UseLocalTime);

        if (s.Proxy is { } p && p.Type != "None")
        {
            f["proxyType"] = p.Type;
            f["proxyAddress"] = p.Address;
            f["proxyPort"] = p.Port.ToString();
            if (p.Username is not null) f["proxyUsername"] = p.Username;
            if (p.Password is not null) f["proxyPassword"] = p.Password;
            if (p.Bypass?.Count > 0) f["proxyBypass"] = string.Join(",", p.Bypass);
        }
        else
        {
            f["proxyType"] = "None";
        }

        return f;
    }
}
