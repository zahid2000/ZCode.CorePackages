using System.Security.Cryptography;

namespace NArchitecture.Core.Security.SmsAuthenticator;

public class SmsAuthenticatorHelper : ISmsAuthenticatorHelper
{
    public virtual Task<string> CreateSmsActivationCode()
    {
        string code = RandomNumberGenerator
            .GetInt32(Convert.ToInt32(Math.Pow(x: 10, y: 6)))
            .ToString()
            .PadLeft(totalWidth: 6, paddingChar: '0');
        return Task.FromResult(code);
    }

    public virtual Task<bool> VerifyCode(string storedCode, string providedCode)
    {
        if (string.IsNullOrWhiteSpace(storedCode) || string.IsNullOrWhiteSpace(providedCode))
            return Task.FromResult(false);

        bool isValid = storedCode.Equals(providedCode, StringComparison.Ordinal);
        return Task.FromResult(isValid);
    }

    public virtual Task<bool> IsCodeExpired(DateTime codeCreatedAt, int expirationMinutes = 5)
    {
        bool isExpired = DateTime.UtcNow > codeCreatedAt.AddMinutes(expirationMinutes);
        return Task.FromResult(isExpired);
    }
}
