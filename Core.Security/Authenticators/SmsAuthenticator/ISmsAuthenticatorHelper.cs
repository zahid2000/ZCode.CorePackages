namespace NArchitecture.Core.Security.SmsAuthenticator;

public interface ISmsAuthenticatorHelper
{
    Task<string> CreateSmsActivationCode();
    Task<bool> VerifyCode(string storedCode, string providedCode);
    Task<bool> IsCodeExpired(DateTime codeCreatedAt, int expirationMinutes = 5);
}
