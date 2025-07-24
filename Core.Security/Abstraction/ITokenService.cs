using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using NArchitecture.Core.Security.Entities;
using ZCode.Core.Security.Models;

namespace ZCode.Core.Security.Abstraction;

public interface ITokenService<TUserId, TRefreshTokenId> where TUserId : IEquatable<TUserId>
{
    AccessToken GenerateToken(IEnumerable<Claim> claims);
    RefreshToken<TRefreshTokenId, TUserId> GenerateRefreshToken(IdentityUser<TUserId> user, string ipAddress);
    // string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token);
    bool IsTokenExpired(string token);
    DateTime? GetTokenExpiration(string token);
    IEnumerable<Claim> GetTokenClaims(string token);
}
