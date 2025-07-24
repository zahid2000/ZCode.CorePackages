using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using ZCode.Core.Security.Abstraction;
using ZCode.Core.Security.Encrypting;
using ZCode.Core.Security.Hashing;
using ZCode.Core.Security.JWT;
using ZCode.Core.Security.Models;
using ZCode.Core.Security.Services;
using NArchitecture.Core.Security.EmailAuthenticator;
using NArchitecture.Core.Security.OtpAuthenticator;
using NArchitecture.Core.Security.OtpAuthenticator.OtpNet;
using NArchitecture.Core.Security.SmsAuthenticator;

namespace ZCode.Core.Security.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSecurityServices<TUserId,TRefreshTokenId>(this IServiceCollection services, IConfiguration configuration)
    where TUserId : IEquatable<TUserId>
    {
        // JWT Settings
        services.Configure<TokenOption>(configuration.GetSection("TokenOptions"));

        // Services
        services.AddScoped<ITokenService<TUserId,TRefreshTokenId>, JwtService<TUserId,TRefreshTokenId>>();
        // services.AddScoped<IHashingService, BCryptHashingService>();
        services.AddScoped<ICurrentUserService, CurrentUserService>();

        // HTTP Context Accessor
        services.AddHttpContextAccessor();

        return services;
    }

    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        var tokenOptions = configuration.GetSection("TokenOptions").Get<TokenOption>();
        
        if (tokenOptions == null)
            throw new InvalidOperationException("TokenOptions configuration is missing");

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = SecurityKeyHelper.CreateSecurityKey(tokenOptions.SecurityKey),
                ValidateIssuer = true,
                ValidIssuer = tokenOptions.Issuer,
                ValidateAudience = true,
                ValidAudience = tokenOptions.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                RequireExpirationTime = true,

            };
        });

        return services;
    }

    public static IServiceCollection AddAuthenticatorServices(this IServiceCollection services)
    {
        // Email Authenticator
        services.AddScoped<IEmailAuthenticatorHelper, EmailAuthenticatorHelper>();

        // OTP Authenticator
        services.AddScoped<IOtpAuthenticatorHelper, OtpNetOtpAuthenticatorHelper>();

        // SMS Authenticator
        services.AddScoped<ISmsAuthenticatorHelper, SmsAuthenticatorHelper>();

        return services;
    }

    public static IServiceCollection AddHashingService(this IServiceCollection services, int workFactor = 12)
    {
        services.AddScoped<IHashingService>(_ => new BCryptHashingService(workFactor));
        return services;
    }

    public static IServiceCollection AddEncryptionService(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<EncryptionOptions>(configuration.GetSection("EncryptionOptions"));

        services.AddScoped<IEncryptionService>(provider =>
        {
            var encryptionOptions = configuration.GetSection("EncryptionOptions").Get<EncryptionOptions>();
            if (encryptionOptions == null)
                throw new InvalidOperationException("EncryptionOptions configuration is missing");

            return new AesEncryptionService(encryptionOptions.Key, encryptionOptions.IV);
        });

        return services;
    }
}
