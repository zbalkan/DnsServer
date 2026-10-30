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
using System.Collections.ObjectModel;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.ApplicationCommon
{
    public sealed class DnsQueryLogMetadata
    {
        public DnsQueryLogMetadata(IReadOnlyDictionary<string, string>? values = null)
        {
            Values = new ReadOnlyDictionary<string, string>(values is null ? new Dictionary<string, string>(0, StringComparer.OrdinalIgnoreCase) : new Dictionary<string, string>(values, StringComparer.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Structured metadata key/value pairs (example keys: <c>source</c>, <c>domain</c>, <c>blockListUrl</c>).
        /// </summary>
        public IReadOnlyDictionary<string, string> Values { get; }

        /// <summary>
        /// Remove user info, query parameters, and fragments before storing a list URL in telemetry.
        /// </summary>
        public static string SanitizeUrl(Uri url)
        {
            UriBuilder sanitized = new UriBuilder(url)
            {
                UserName = string.Empty,
                Password = string.Empty,
                Query = string.Empty,
                Fragment = string.Empty
            };

            return sanitized.Uri.AbsoluteUri;
        }

    }

    /// <summary>
    /// Carries optional decision metadata during processing of one incoming DNS query.
    /// This is internal logging state; it must never be stored in DnsDatagram.Tag or sent on the wire.
    /// </summary>
    public sealed class DnsQueryLogContext
    {
        public DnsQueryLogMetadata? BlockingMetadata { get; set; }
    }

    public static class DnsServerResponseClassifier
    {
        public static DnsServerResponseType GetResponseType(object? tag)
        {
            return tag is DnsServerResponseType responseType ? responseType : DnsServerResponseType.Recursive;
        }
    }

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
        Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response);
    }

    /// <summary>
    /// Allows a DNS App to receive extended query log metadata.
    /// </summary>
    public interface IDnsQueryLoggerEx : IDnsQueryLogger
    {
        /// <summary>
        /// Allows a DNS App to log incoming DNS requests and responses, including metadata that may not be present in the wire response.
        /// </summary>
        /// <param name="timestamp">The time stamp of the log entry.</param>
        /// <param name="request">The incoming DNS request that was received.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <param name="protocol">The protocol using which the request was received.</param>
        /// <param name="response">The DNS response that was sent.</param>
        /// <param name="metadata">Optional metadata for logging.</param>
        Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response, DnsQueryLogMetadata? metadata);
    }
}
