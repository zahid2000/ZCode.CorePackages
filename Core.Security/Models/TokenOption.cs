namespace ZCode.Core.Security.Models;

public class TokenOption
{
    public string SecurityKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    /// <summary>
    /// Token expiration time in minutes.
    /// </summary>
    public int ExpirationMinutes { get; set; } = 60;
    /// <summary>
    /// Refresh token time in days.
    /// </summary>
    public int RefreshTokenTTL { get; set; } = 7;
}
