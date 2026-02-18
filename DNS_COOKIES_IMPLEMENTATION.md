# DNS Cookies Implementation - Fixes and Usage

## Issues Fixed

The original implementation attempt had several issues that prevented it from working correctly:

### 1. Missing Security Classes
The code referenced `Security.DnsCookieSecretManager` and `Security.DnsCookieValidator` but these classes didn't exist. Created:
- **DnsCookieSecretManager.cs**: Manages cookie secrets with automatic rotation and persistence
- **DnsCookieValidator.cs**: Validates incoming cookies and generates response cookies per RFC 9018

### 2. HTML Entity Issues
The diff contained HTML entities that would have caused compilation errors:
- `&gt;` → `>` (greater than)
- `&amp;` → `&` (ampersand)

### 3. Missing TechnitiumLibrary Changes
The EDnsCookieOptionData class needed to be added to TechnitiumLibrary.Net. Applied the patch from `technitium-dns-cookies.patch`.

### 4. Configuration Persistence
Added proper reading/writing of DNS cookie settings in config file with backwards compatibility for old config files without cookie settings.

## Implementation Details

### Secret Management
- **Automatic Secret Generation**: First run creates a random 32-byte secret
- **Rotation Support**: Timer-based automatic rotation (default 24 hours)
- **Fallback to Previous Secret**: Validates cookies with both current and previous secret for smooth rotation
- **Persistent Storage**: Secrets saved to `dns.cookies.state` file

### Cookie Validation (RFC 9018)
- **Structure**: Version (1 byte) | Reserved (1 byte) | Timestamp (4 bytes) | Hash (8 bytes)
- **HMAC-SHA256-64**: Uses HMAC-SHA256, truncated to 8 bytes
- **Timestamp Validation**: 5-minute tolerance window
- **IP Address Binding**: Cookies are bound to client IP address

### Server Behavior
1. **Missing Cookie**: Increments counter, processes query normally
2. **Invalid Cookie**: Returns BADCOOKIE response with TC flag set and valid cookie
3. **Valid Cookie**: Increments valid counter, processes query normally
4. **Response Generation**: Attaches server cookie when:
   - Client sends cookie without server part (first request)
   - `_dnsCookiesAlwaysEcho` is enabled

## Configuration

DNS Cookies are configured via the following settings (stored in config file):

```csharp
_dnsCookiesEnabled = false;              // Enable/disable DNS cookies
_dnsCookiesSecretFile = "dns.cookies.state";  // Secret storage file
_dnsCookiesRotationPeriodHours = 24;    // Secret rotation interval
_dnsCookiesSetTcOnBadCookie = true;     // Set TC flag on BADCOOKIE (RFC 7873)
_dnsCookiesAlwaysEcho = false;          // Always send server cookie in response
```

## Testing Results

All tests passed successfully:
- ✅ Secret generation and persistence
- ✅ Secret rotation with fallback
- ✅ Cookie generation per RFC 9018 structure
- ✅ Cookie validation with correct IP
- ✅ Cookie rejection with wrong IP
- ✅ Validation with previous secret after rotation
- ✅ Proper RFC 9018 structure (version, reserved, timestamp, hash)

## Observability

The implementation includes counters for monitoring:
```csharp
_cookieValid          // Valid cookie validations
_cookieInvalid        // Invalid cookie rejections
_cookieMissing        // Requests without cookies
_cookieBadcookieSent  // BADCOOKIE responses sent
```

These can be exposed via statistics API for monitoring.

## Usage Example

### Enable DNS Cookies
```csharp
// In DNS server configuration
_dnsCookiesEnabled = true;
InitDnsCookiesIfEnabled();
```

### Query Processing Flow
1. Client sends DNS query with client cookie (8 bytes)
2. Server validates any included server cookie
3. If invalid, server responds with BADCOOKIE and valid cookie
4. Client retries with valid cookie
5. Server processes query normally and includes server cookie in response

## Future Enhancements

Possible improvements for production use:
1. **Configuration API**: Expose cookie settings via web API
2. **Statistics Dashboard**: Display cookie counters in admin panel
3. **Rate Limiting**: Use cookie validation for rate limiting decisions
4. **Monitoring Alerts**: Alert on high invalid cookie rates (potential attack)
5. **Custom Rotation Schedule**: Per-zone or time-based rotation policies
6. **Secret Key Import/Export**: For multi-server deployments

## References

- RFC 7873: DNS Cookies (original specification)
- RFC 9018: Interoperable DNS Cookies (current standard)
- RFC 6891: EDNS(0) specification
- BIND 9 DNS Cookies: https://bind9.readthedocs.io/en/latest/chapter7.html#server-cookies
- Knot DNS Cookies: https://www.knot-dns.cz/docs/latest/html/configuration.html#server-section
