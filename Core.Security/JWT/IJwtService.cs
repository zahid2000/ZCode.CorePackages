using System.Security.Claims;

namespace ZCode.Core.Security.JWT;

public interface IJwtService
{
    string GenerateToken(IEnumerable<Claim> claims, TimeSpan? expiration = null);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token);
    bool IsTokenExpired(string token);
    DateTime? GetTokenExpiration(string token);
    IEnumerable<Claim> GetTokenClaims(string token);
}
