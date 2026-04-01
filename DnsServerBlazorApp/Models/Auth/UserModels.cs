using System.Text.Json.Serialization;

namespace DnsServerBlazorApp.Models.Auth;

public sealed class UserInfo
{
    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("disabled")]
    public bool Disabled { get; set; }

    [JsonPropertyName("totpEnabled")]
    public bool TotpEnabled { get; set; }

    [JsonPropertyName("memberOf")]
    public List<string>? MemberOf { get; set; }

    [JsonPropertyName("sessions")]
    public List<SessionInfo>? Sessions { get; set; }
}

public sealed class UserListResponse
{
    [JsonPropertyName("users")]
    public List<UserInfo>? Users { get; init; }
}

public sealed class SessionInfo
{
    [JsonPropertyName("token")]
    public string? Token { get; init; }

    [JsonPropertyName("partialToken")]
    public string? PartialToken { get; init; }

    [JsonPropertyName("tokenName")]
    public string? TokenName { get; init; }

    [JsonPropertyName("username")]
    public string? Username { get; init; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; init; }

    [JsonPropertyName("isApiToken")]
    public bool IsApiToken { get; init; }

    [JsonPropertyName("createdOn")]
    public DateTime? CreatedOn { get; init; }

    [JsonPropertyName("lastSeen")]
    public DateTime? LastSeen { get; init; }

    [JsonPropertyName("lastSeenRemoteAddress")]
    public string? LastSeenRemoteAddress { get; init; }

    [JsonPropertyName("lastSeenUserAgent")]
    public string? LastSeenUserAgent { get; init; }
}

public sealed class SessionListResponse
{
    [JsonPropertyName("sessions")]
    public List<SessionInfo>? Sessions { get; init; }
}

public sealed class GroupInfo
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("members")]
    public List<string>? Members { get; set; }
}

public sealed class GroupListResponse
{
    [JsonPropertyName("groups")]
    public List<GroupInfo>? Groups { get; init; }
}

public sealed class ApiTokenResponse
{
    [JsonPropertyName("token")]
    public string? Token { get; init; }
}

public sealed class TotpSetupResponse
{
    [JsonPropertyName("secret")]
    public string? Secret { get; init; }

    [JsonPropertyName("qrCodeUrl")]
    public string? QrCodeUrl { get; init; }
}
