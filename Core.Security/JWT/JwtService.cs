using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ZCode.Core.Security.Abstraction;
using ZCode.Core.Security.Encrypting;
using ZCode.Core.Security.Models;
using NArchitecture.Core.Security.Entities;
using Microsoft.AspNetCore.Identity;
using ZCode.Core.Security.Extensions;
using System.Collections.Immutable;

namespace ZCode.Core.Security.JWT;

public class JwtService<TUserId, TRefreshTokenId> : ITokenService<TUserId, TRefreshTokenId>
 where TUserId : IEquatable<TUserId>
{
    private readonly TokenOption _tokenOptions;
    private DateTime _tokenExpiration;
    private readonly JwtSecurityTokenHandler _tokenHandler;

    public JwtService(IOptions<TokenOption> tokenOptions)
    {
        _tokenOptions = tokenOptions.Value;
        _tokenExpiration = DateTime.UtcNow.AddMinutes(_tokenOptions.ExpirationMinutes);
        _tokenHandler = new JwtSecurityTokenHandler();
    }

    public AccessToken GenerateToken(IEnumerable<Claim> claims)
    {
        JwtHeader jwtHeader = CreateJwtHeader();
        JwtPayload jwtPayload = CreateJwtPayload(claims.ToList());

        JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(jwtHeader, jwtPayload);
        var token = _tokenHandler.WriteToken(jwtSecurityToken);
        return new AccessToken(token, _tokenExpiration);
    }

    // public string GenerateRefreshToken()
    // {
    //     var randomBytes = new byte[64];
    //     using var rng = RandomNumberGenerator.Create();
    //     rng.GetBytes(randomBytes);
    //     return Convert.ToBase64String(randomBytes);
    // }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        try
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenOptions.SecurityKey));

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = true,
                ValidIssuer = _tokenOptions.Issuer,
                ValidateAudience = true,
                ValidAudience = _tokenOptions.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var principal = _tokenHandler.ValidateToken(token, validationParameters, out _);
            return principal;
        }
        catch
        {
            return null;
        }
    }

    public bool IsTokenExpired(string token)
    {
        try
        {
            var jwtToken = _tokenHandler.ReadJwtToken(token);
            return jwtToken.ValidTo < DateTime.UtcNow;
        }
        catch
        {
            return true;
        }
    }

    public DateTime? GetTokenExpiration(string token)
    {
        try
        {
            var jwtToken = _tokenHandler.ReadJwtToken(token);
            return jwtToken.ValidTo;
        }
        catch
        {
            return null;
        }
    }

    public IEnumerable<Claim> GetTokenClaims(string token)
    {
        try
        {
            var jwtToken = _tokenHandler.ReadJwtToken(token);
            return jwtToken.Claims;
        }
        catch
        {
            return Enumerable.Empty<Claim>();
        }
    }
    private JwtPayload CreateJwtPayload(List<Claim> claims)
    {
        return new JwtPayload(
           issuer: _tokenOptions.Issuer,
           audience: _tokenOptions.Audience,
           claims: claims,
           notBefore: DateTime.UtcNow,
           expires: _tokenExpiration);
    }

    private JwtHeader CreateJwtHeader()
    {
        SecurityKey securityKey = SecurityKeyHelper.CreateSecurityKey(_tokenOptions.SecurityKey);
        SigningCredentials signingCredentials = SigninCredentialsHelper.CreateSigninCredentials(securityKey);
        JwtHeader jwtHeader = new JwtHeader(signingCredentials);
        return jwtHeader;
    }

    public RefreshToken<TRefreshTokenId, TUserId> GenerateRefreshToken(IdentityUser<TUserId> user, string ipAddress)
    {
        return new RefreshToken<TRefreshTokenId, TUserId>()
        {
            UserId = user.Id,
            Token = randomRefreshToken(),
            ExpirationDate = DateTime.UtcNow.AddDays(_tokenOptions.RefreshTokenTTL),
            CreatedByIp = ipAddress
        };
    }
    private string randomRefreshToken()
    {
        byte[] numberByte = new byte[32];
        using var random = RandomNumberGenerator.Create();
        random.GetBytes(numberByte);
        return Convert.ToBase64String(numberByte);
    } 
}
