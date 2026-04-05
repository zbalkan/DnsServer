/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.ApplicationCommon
{
    public enum DnsServerResponseType : byte
    {
        Authoritative = 1,
        Recursive = 2,
        Cached = 3,
        Blocked = 4,
        UpstreamBlocked = 5,
        UpstreamBlockedCached = 6,
        Dropped = 7
    }

    /// <summary>
    /// Carries optional enriched metadata about a DNS response, intended for logging purposes only.
    /// This object does not affect the DNS wire format in any way.
    /// </summary>
    public sealed class DnsQueryLogMetadata
    {
        /// <summary>
        /// The name of the DNS application that produced this response (e.g. "MispConnector").
        /// </summary>
        public string? SourcePlugin { get; init; }

        /// <summary>
        /// Structured key/value pairs describing why the request was blocked or otherwise handled.
        /// Serialises as a JSON object so consumers can read individual fields without string splitting.
        /// </summary>
        public Dictionary<string, string>? BlockingReason { get; init; }
    }

    /// <summary>
    /// Carrier that may be stored in <see cref="TechnitiumLibrary.Net.Dns.DnsDatagram.Tag"/> by the
    /// DNS server core to provide structured response details for logging.
    /// During the current transition, consumers must handle both a raw
    /// <see cref="DnsServerResponseType"/> value and a <see cref="DnsResponseTag"/> instance in
    /// <see cref="TechnitiumLibrary.Net.Dns.DnsDatagram.Tag"/>. When present, this carrier allows
    /// blocking apps to attach <see cref="DnsQueryLogMetadata"/> that survives through to
    /// <see cref="IDnsQueryLogger.InsertLogAsync"/>. Use <see cref="GetResponseType"/> to decode the
    /// tag safely regardless of which shape is present.
    /// </summary>
    public sealed class DnsResponseTag
    {
        /// <summary>The categorised response type set by the DNS server core.</summary>
        public DnsServerResponseType ResponseType { get; init; }

        /// <summary>
        /// Optional metadata populated by a blocking app; <c>null</c> for non-blocking responses.
        /// </summary>
        public DnsQueryLogMetadata? Metadata { get; init; }

        /// <summary>
        /// Decodes the response type from a <see cref="TechnitiumLibrary.Net.Dns.DnsDatagram.Tag"/>
        /// value, handling both the new <see cref="DnsResponseTag"/> carrier and the legacy boxed
        /// <see cref="DnsServerResponseType"/> enum value that the core still emits on many code paths.
        /// Falls back to <see cref="DnsServerResponseType.Recursive"/> when the tag is absent or of
        /// an unrecognised type.
        /// </summary>
        /// <param name="tag">The value of <see cref="TechnitiumLibrary.Net.Dns.DnsDatagram.Tag"/>.</param>
        public static DnsServerResponseType GetResponseType(object? tag) => tag switch
        {
            DnsResponseTag dnsResponseTag => dnsResponseTag.ResponseType,
            DnsServerResponseType dnsServerResponseType => dnsServerResponseType,
            _ => DnsServerResponseType.Recursive
        };
    }

    /// <summary>
    /// Allows a DNS App to log incoming DNS requests and their corresponding responses.
    /// </summary>
    public interface IDnsQueryLogger
    {
        /// <summary>
        /// Allows a DNS App to log incoming DNS requests and responses. This method is called by the DNS Server after an incoming request is processed and a response is sent.
        /// </summary>
        /// <param name="timestamp">The time stamp of the log entry.</param>
        /// <param name="request">The incoming DNS request that was received.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <param name="protocol">The protocol using which the request was received.</param>
        /// <param name="response">The DNS response that was sent.</param>
        /// <param name="metadata">Optional enriched metadata provided by a blocking app; <c>null</c> when not available.</param>
        Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response, DnsQueryLogMetadata? metadata = null);
    }
}
