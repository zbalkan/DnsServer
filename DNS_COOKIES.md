# DNS Cookies Support Implementation

## Overview
This document describes the DNS Cookies implementation added to support RFC 7873 and RFC 9018 specifications in the DnsServer project through updates to the TechnitiumLibrary.Net dependency.

## Background
DNS Cookies provide a lightweight transaction security mechanism to protect against:
- Denial of Service (DoS) attacks
- DNS amplification attacks
- Off-path attacks
- Query/response spoofing

## Implementation

### Changes to TechnitiumLibrary.Net

The implementation adds DNS Cookies support to the TechnitiumLibrary.Net library (separate repository):

1. **New File: `TechnitiumLibrary.Net/Dns/EDnsOptions/EDnsCookieOptionData.cs`**
   - Implements `EDnsOptionData` abstract class
   - Handles client cookie (8 bytes) and optional server cookie (8-32 bytes)
   - Provides parsing and serialization according to RFC 7873 and RFC 9018
   - Includes validation, JSON serialization, and debugging support

2. **Modified File: `TechnitiumLibrary.Net/Dns/EDnsOptions/EDnsOption.cs`**
   - Added `EDnsOptionCode.COOKIE` case to parser
   - Enables automatic parsing of DNS Cookie options from packets

### RFC Compliance

#### RFC 7873 - DNS Cookies (May 2016)
- ✅ Client cookie: Fixed 8 bytes (64 bits)
- ✅ Server cookie: Variable 8-32 bytes
- ✅ EDNS option code: 10
- ✅ Supports both query (client cookie only) and response (client + server cookie) scenarios

#### RFC 9018 - Interoperable DNS Cookies (April 2021)
- ✅ Server cookie structure with version, timestamp, and hash fields
- ✅ Recommended 16-byte server cookie length
- ✅ Support for HMAC-SHA256-64 hash algorithm
- ✅ Timestamp handling for replay protection

## Building with Updated Library

### Prerequisites
- .NET 9.0 SDK
- TechnitiumLibrary repository cloned as sibling to DnsServer

### Build Steps

```bash
# Clone repositories (if not already done)
git clone https://github.com/TechnitiumSoftware/TechnitiumLibrary.git
git clone https://github.com/zbalkan/DnsServer.git

# Apply DNS Cookies patch to TechnitiumLibrary
cd TechnitiumLibrary
# Apply the patch file or manually add the changes

# Build TechnitiumLibrary components
dotnet build TechnitiumLibrary/TechnitiumLibrary.csproj -c Release
dotnet build TechnitiumLibrary.IO/TechnitiumLibrary.IO.csproj -c Release
dotnet build TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj -c Release
dotnet build TechnitiumLibrary.ByteTree/TechnitiumLibrary.ByteTree.csproj -c Release
dotnet build TechnitiumLibrary.Security.OTP/TechnitiumLibrary.Security.OTP.csproj -c Release

# Build DnsServer with updated library
cd ../DnsServer
dotnet build DnsServerCore/DnsServerCore.csproj -c Release
```

## Usage Example

```csharp
using TechnitiumLibrary.Net.Dns.EDnsOptions;

// Creating a DNS query with client cookie
byte[] clientCookie = GenerateRandomBytes(8);
var cookieOption = new EDnsOption(
    EDnsOptionCode.COOKIE, 
    new EDnsCookieOptionData(clientCookie)
);

// Creating a DNS response with client + server cookie
byte[] serverCookie = ComputeServerCookie(clientCookie, clientIP, timestamp);
var responseCookieOption = new EDnsOption(
    EDnsOptionCode.COOKIE,
    new EDnsCookieOptionData(clientCookie, serverCookie)
);

// Parsing cookies from DNS packet
if (option.Data is EDnsCookieOptionData cookieData)
{
    byte[] cc = cookieData.ClientCookie;
    byte[] sc = cookieData.ServerCookie; // May be null in queries
    
    // Validate and process cookie
    if (sc != null && ValidateServerCookie(cc, sc, clientIP))
    {
        // Cookie is valid
    }
}
```

## Testing

The implementation has been tested with:
- Client cookie only (8 bytes)
- Client + server cookie combinations (8, 16, 24, 32 byte server cookies)
- Serialization and deserialization round-trips
- JSON serialization
- Raw byte parsing from DNS packets
- Edge case validation (minimum/maximum sizes)
- Error handling for invalid cookie sizes

All tests passed successfully.

## Future Enhancements

The current implementation provides the foundational building blocks for DNS Cookies. Future work could include:

### Server-Side Features
- Automatic server cookie generation using HMAC-SHA256-64
- Secret key management with automatic rotation
- Timestamp validation and staleness checking
- Integration with client IP address for cookie computation
- Cookie verification in request processing
- Statistics and monitoring

### Client-Side Features
- Automatic client cookie generation
- Cookie caching per upstream server
- Cookie refresh on expiry
- Retry logic for cookie-based errors

### Configuration
- Enable/disable DNS Cookies per zone
- Configure secret keys and rotation schedules
- Set timestamp tolerance windows
- Cookie statistics and logging

### Advanced Features (from BIND/Knot)
- Multiple secret keys with fallback support
- Per-client cookie tracking
- Cookie-based rate limiting
- Integration with DNSSEC

## References

- [RFC 7873: Domain Name System (DNS) Cookies](https://datatracker.ietf.org/doc/html/rfc7873)
- [RFC 9018: Interoperable Domain Name System (DNS) Cookies](https://datatracker.ietf.org/doc/html/rfc9018)
- [RFC 6891: Extension Mechanisms for DNS (EDNS(0))](https://datatracker.ietf.org/doc/html/rfc6891)
- [BIND 9 DNS Cookies Implementation](https://bind9.readthedocs.io/en/latest/chapter7.html#server-cookies)
- [Knot DNS Cookies](https://www.knot-dns.cz/docs/latest/html/configuration.html#server-section)

## Security Considerations

DNS Cookies are designed to provide lightweight protection against:
- Reflection attacks using DNS
- Amplification attacks
- Off-path attacks
- Forgery of DNS responses

However, DNS Cookies:
- Are NOT a replacement for DNSSEC
- Do NOT provide encryption (use DNS-over-TLS/HTTPS for that)
- Do NOT authenticate the client (use TSIG for that)
- Should be combined with other security mechanisms for defense-in-depth

## License

The implementation follows the same GPL-3.0 license as TechnitiumLibrary and DnsServer.

Copyright (C) 2025 Shreyas Zare (shreyas@technitium.com)
