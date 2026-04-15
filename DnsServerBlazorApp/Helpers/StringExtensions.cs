namespace DnsServerBlazorApp.Helpers;

public static class StringExtensions
{
    public static string ToShortClassName(this string? classPath, string fallback = "?")
    {
        if (string.IsNullOrEmpty(classPath))
            return fallback;

        var dot = classPath.LastIndexOf('.');
        return dot >= 0 ? classPath[(dot + 1)..] : classPath;
    }

    public static string GetParentDomain(this string? domain)
    {
        if (string.IsNullOrEmpty(domain))
            return string.Empty;

        var i = domain.IndexOf('.');
        return i < 0 ? string.Empty : domain[(i + 1)..];
    }
}
