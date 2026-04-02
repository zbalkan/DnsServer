using DnsServerBlazorApp.Models;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace DnsServerBlazorApp.Services;

/// <summary>
/// Wraps all HTTP calls to the Technitium REST API.
/// Mirrors the HTTPRequest() helper from the original common.js:
///   – attaches the session token to every request
///   – normalises the envelope status ("ok", "error", "invalid-token", "2fa-required")
///   – exposes callbacks via ApiResult&lt;T&gt; so callers react to each status
/// </summary>
public sealed class ApiService
{
    private readonly HttpClient    _http;
    private readonly SessionService _session;

    private static readonly JsonSerializerOptions _json = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition      = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public ApiService(HttpClient http, SessionService session)
    {
        _http    = http;
        _session = session;
    }

    // ── Public API ────────────────────────────────────────────────────

    /// <summary>GET request. Returns an <see cref="ApiResult{T}"/> with <c>IsNetworkError</c> set on failure.</summary>
    public Task<ApiResult<T>> GetAsync<T>(string path, CancellationToken ct = default)
        => SendAsync<T>(HttpMethod.Get, BuildUrl(path), null, ct);

    /// <summary>POST request with URL-encoded form data.</summary>
    public Task<ApiResult<T>> PostAsync<T>(string path, Dictionary<string, string> form,
        CancellationToken ct = default)
    {
        var content = new FormUrlEncodedContent(form);
        return SendAsync<T>(HttpMethod.Post, BuildUrl(path), content, ct);
    }

    /// <summary>POST request with multipart form (file uploads).</summary>
    public Task<ApiResult<T>> PostMultipartAsync<T>(string path, MultipartFormDataContent form,
        CancellationToken ct = default)
        => SendAsync<T>(HttpMethod.Post, BuildUrl(path), form, ct);

    /// <summary>GET that opens a new browser tab (e.g. backup download).</summary>
    public string BuildDownloadUrl(string path) => BuildUrl(path);

    // ── Internals ─────────────────────────────────────────────────────

    private string BuildUrl(string path)
    {
        var token = _session.Token;
        var sep   = path.Contains('?') ? "&" : "?";
        return token is { Length: > 0 } ? $"{path}{sep}token={Uri.EscapeDataString(token)}" : path;
    }

    private async Task<ApiResult<T>> SendAsync<T>(
        HttpMethod method, string url, HttpContent? content, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(method, url) { Content = content };
            using var resp = await _http.SendAsync(req, ct);

            if (!resp.IsSuccessStatusCode)
                return ApiResult<T>.NetworkError($"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}");

            var envelope = await resp.Content.ReadFromJsonAsync<ApiResponse<T>>(_json, ct);
            if (envelope is null)
                return ApiResult<T>.NetworkError("Empty response from server.");

            return new ApiResult<T>(envelope);
        }
        catch (OperationCanceledException)
        {
            return ApiResult<T>.NetworkError("Request was cancelled.");
        }
        catch (Exception ex)
        {
            return ApiResult<T>.NetworkError(ex.Message);
        }
    }
}

// ── Result wrapper ─────────────────────────────────────────────────────────

/// <summary>
/// Outcome of an API call. Exactly mirrors the JS switch on response.status.
/// </summary>
public sealed class ApiResult<T>
{
    public bool   IsOk           { get; }
    public bool   IsInvalidToken { get; }
    public bool   Is2FARequired  { get; }
    public bool   IsError        { get; }
    public bool   IsNetworkError { get; }

    public T?      Data         { get; }
    public string? ErrorMessage { get; }

    // Full envelope (token, displayName, info at top level on login)
    public ApiResponse<T>? Envelope { get; }

    internal ApiResult(ApiResponse<T> env)
    {
        Envelope       = env;
        Data           = env.Response;
        ErrorMessage   = env.ErrorMessage;
        IsOk           = env.IsOk;
        IsInvalidToken = env.IsInvalidToken;
        Is2FARequired  = env.Is2FARequired;
        IsError        = env.IsError;
    }

    private ApiResult(string networkError)
    {
        IsNetworkError = true;
        ErrorMessage   = networkError;
    }

    internal static ApiResult<T> NetworkError(string msg) => new(msg);

    public string DisplayError =>
        ErrorMessage ?? (IsInvalidToken ? "Session expired. Please log in again."
                       : Is2FARequired  ? "Two-factor authentication required."
                       : IsNetworkError ? "Unable to connect to the server."
                       : "Unknown error.");
}
