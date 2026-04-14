using DnsServerBlazorApp.Models;
using System.Text.Json;

namespace DnsServerBlazorApp.Services;

/// <summary>
/// Wraps all HTTP calls to the Technitium REST API:
///   – attaches the session token to every request
///   – normalises the envelope status ("ok", "error", "invalid-token", "2fa-required")
///   – exposes results via <see cref="ApiResult{T}"/> so callers react to each status
/// </summary>
public sealed class ApiService
{
    private readonly HttpClient _http;
    private readonly SessionService _session;
    private readonly ILogger<ApiService> _logger;

    private static readonly JsonSerializerOptions _json = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    // HttpClient is registered with BaseAddress = NavigationManager.BaseUri in
    // BlazorHostingExtensions so it is always correctly configured in every
    // rendering phase (pre-render and SignalR circuit alike).
    public ApiService(HttpClient http, SessionService session, ILogger<ApiService> logger)
    {
        _http = http;
        _session = session;
        _logger = logger;
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
        var sep = path.Contains('?') ? "&" : "?";
        return token is { Length: > 0 } ? $"{path}{sep}token={Uri.EscapeDataString(token)}" : path;
    }

    // Strip the token query parameter before logging so credentials never appear in logs.
    private static string SanitizeUrl(string url)
    {
        var idx = url.IndexOf("token=", StringComparison.OrdinalIgnoreCase);
        return idx < 0 ? url : url[..idx] + "token=***";
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
        catch (JsonException ex)
        {
            // Log with full path/position so model mismatches are immediately obvious
            // during development without needing browser DevTools.
            _logger.LogError(ex,
                "JSON deserialization failed for {Method} {Url} — " +
                "Path: {Path} | Line: {Line} | Pos: {Pos} | " +
                "Check that the C# model property type and [JsonPropertyName] match the API response. " +
                "Response type parameter: {ResponseType}",
                method, SanitizeUrl(url),
                ex.Path, ex.LineNumber, ex.BytePositionInLine,
                typeof(T).Name);
            return ApiResult<T>.NetworkError($"Response parse error at {ex.Path}: {ex.Message}");
        }
        catch (OperationCanceledException)
        {
            return ApiResult<T>.NetworkError("Request was cancelled.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "API request failed for {Method} {Url}", method, SanitizeUrl(url));
            return ApiResult<T>.NetworkError(ex.Message);
        }
    }
}

// ── Result wrapper ─────────────────────────────────────────────────────────

/// <summary>Outcome of an API call.</summary>
public sealed class ApiResult<T>
{
    public bool IsOk { get; }
    public bool IsInvalidToken { get; }
    public bool Is2FARequired { get; }
    public bool IsError { get; }
    public bool IsNetworkError { get; }

    public T? Data { get; }
    public string? ErrorMessage { get; }

    // Full envelope (token, displayName, info at top level on login)
    public ApiResponse<T>? Envelope { get; }

    internal ApiResult(ApiResponse<T> env)
    {
        Envelope = env;
        Data = env.Response;
        ErrorMessage = env.ErrorMessage;
        IsOk = env.IsOk;
        IsInvalidToken = env.IsInvalidToken;
        Is2FARequired = env.Is2FARequired;
        IsError = env.IsError;
    }

    private ApiResult(string networkError)
    {
        IsNetworkError = true;
        ErrorMessage = networkError;
    }

    internal static ApiResult<T> NetworkError(string msg) => new(msg);

    public string DisplayError
    {
        get
        {
            if (IsInvalidToken)
            {
                return ErrorMessage ?? "Session expired. Please log in again.";
            }

            if (Is2FARequired)
            {
                return ErrorMessage ?? "Two-factor authentication required.";
            }

            if (IsNetworkError)
            {
                return ErrorMessage ?? "Unable to connect to the server.";
            }

            return ErrorMessage ?? "Unknown error.";
        }
    }
}
