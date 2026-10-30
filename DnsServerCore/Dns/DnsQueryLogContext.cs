/*
Technitium DNS Server
Copyright (C) 2026 Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
*/

using DnsServerCore.ApplicationCommon;

namespace DnsServerCore.Dns
{
    /// <summary>
    /// Carries private blocking provenance for one incoming query, independently of
    /// DnsDatagram.Tag and of any EDNS data in the response.
    /// </summary>
    internal sealed class DnsQueryLogContext
    {
        public DnsQueryLogMetadata BlockingMetadata { get; set; }
    }
}
