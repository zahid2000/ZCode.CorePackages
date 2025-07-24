using OtpNet;

namespace NArchitecture.Core.Security.OtpAuthenticator.OtpNet;

public class OtpNetOtpAuthenticatorHelper : IOtpAuthenticatorHelper
{
    public Task<byte[]> GenerateSecretKey()
    {
        byte[] key = KeyGeneration.GenerateRandomKey(20);

        string base32String = Base32Encoding.ToString(key);
        byte[] base32Bytes = Base32Encoding.ToBytes(base32String);

        return Task.FromResult(base32Bytes);
    }

    public Task<string> ConvertSecretKeyToString(byte[] secretKey)
    {
        string base32String = Base32Encoding.ToString(secretKey);
        return Task.FromResult(base32String);
    }

    public Task<bool> VerifyCode(byte[] secretKey, string code)
    {
        Totp totp = new(secretKey);

        string totpCode = totp.ComputeTotp(DateTime.UtcNow);

        bool result = totpCode == code;
        return Task.FromResult(result);
    }

    public Task<string> GenerateQrCodeUri(byte[] secretKey, string accountName, string issuer)
    {
        string base32Secret = Base32Encoding.ToString(secretKey);
        string qrCodeUri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(accountName)}?secret={base32Secret}&issuer={Uri.EscapeDataString(issuer)}";
        return Task.FromResult(qrCodeUri);
    }
}
