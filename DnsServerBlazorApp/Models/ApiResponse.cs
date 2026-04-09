using DnsServerBlazorApp.Models.Auth;
using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models;

/// <summary>
/// Envelope returned by every Technitium API call.
/// status: "ok" | "error" | "invalid-token" | "2fa-required"
/// </summary>
public class ApiResponse<T>
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("errorMessage")]
    public string? ErrorMessage { get; set; }

    [JsonPropertyName("innerErrorMessage")]
    public string? InnerErrorMessage { get; set; }

    [JsonPropertyName("response")]
    public T? Response { get; set; }

    // Fields present on login / session responses at the top level
    [JsonPropertyName("token")]
    public string? Token { get; set; }

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("totpEnabled")]
    public bool TotpEnabled { get; set; }

    [JsonPropertyName("info")]
    public ServerInfo? Info { get; set; }

    public bool IsOk           => Status == "ok";
    public bool IsInvalidToken => Status == "invalid-token";
    public bool Is2FARequired  => Status == "2fa-required";
    public bool IsError        => Status == "error";
}

/// <summary>Untyped convenience wrapper for calls that return no response body.</summary>
public sealed class ApiResponse : ApiResponse<object> { }
