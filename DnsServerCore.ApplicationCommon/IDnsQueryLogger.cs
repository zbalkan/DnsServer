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
    /// <summary>
    /// Optional out-of-band metadata attached to a DNS response by the component that handled the
    /// request (e.g., a built-in blocking zone or a DNS App plug-in).  This object does not affect
    /// the DNS wire format and is only visible to <see cref="IDnsQueryLogger"/> implementations.
    /// </summary>
    public sealed class DnsQueryLogMetadata
    {
        /// <summary>
        /// Identifies the component that produced this response.
        /// Examples: <c>"blocked-zone"</c>, <c>"block-list-zone"</c>, <c>"AdvancedBlockingApp"</c>.
        /// </summary>
        public string? Source { get; init; }

        /// <summary>
        /// Human-readable reason the request was handled in a special way, e.g. the matched domain
        /// or a short description such as <c>"regex match"</c>.
        /// </summary>
        public string? Reason { get; init; }

        /// <summary>
        /// Optional reference that provides additional context, such as a block-list URL or a
        /// rule identifier.
        /// </summary>
        public string? Reference { get; init; }

        /// <summary>
        /// Non-hardcoded supplementary fields supplied by the source component.
        /// Keys are case-insensitive.  May be <see langword="null"/> when no extra data is present.
        /// </summary>
        public IReadOnlyDictionary<string, string>? AdditionalData { get; init; }
    }

    public sealed class DnsServerResponseMetadata
    {
        public DnsServerResponseMetadata(DnsServerResponseType responseType, DnsQueryLogMetadata? logMetadata = null)
        {
            ResponseType = responseType;
            LogMetadata = logMetadata;
        }

        public DnsServerResponseType ResponseType { get; }
        public DnsQueryLogMetadata? LogMetadata { get; }
    }

    public static class DnsServerResponseTag
    {
        public static DnsServerResponseType GetResponseType(object? tag)
        {
            if (tag is null)
                return DnsServerResponseType.Recursive;

            if (tag is DnsServerResponseType responseType)
                return responseType;

            if (tag is DnsServerResponseMetadata responseMetadata)
                return responseMetadata.ResponseType;

            return DnsServerResponseType.Recursive;
        }

        public static DnsQueryLogMetadata? GetLogMetadata(object? tag)
        {
            if (tag is DnsServerResponseMetadata responseMetadata)
                return responseMetadata.LogMetadata;

            return null;
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
        /// Allows a DNS App to log incoming DNS requests and responses. This method is called by
        /// the DNS Server after an incoming request is processed and a response is sent.
        /// </summary>
        /// <param name="timestamp">The time stamp of the log entry.</param>
        /// <param name="request">The incoming DNS request that was received.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <param name="protocol">The protocol using which the request was received.</param>
        /// <param name="response">The DNS response that was sent.</param>
        /// <param name="metadata">
        /// Optional out-of-band metadata attached by the component that produced <paramref name="response"/>
        /// (e.g. blocking zone, block-list zone, or a DNS App plug-in).
        /// May be <see langword="null"/> for non-blocked or non-enriched responses.
        /// </param>
        Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response, DnsQueryLogMetadata? metadata = null);
    }
}
