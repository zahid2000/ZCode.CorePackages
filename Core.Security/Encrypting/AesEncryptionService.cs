using System.Security.Cryptography;
using System.Text;

namespace ZCode.Core.Security.Encrypting;

public class AesEncryptionService : IEncryptionService
{
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public AesEncryptionService(string key, string iv)
    {
        if (string.IsNullOrEmpty(key))
            throw new ArgumentException("Key cannot be null or empty", nameof(key));
        
        if (string.IsNullOrEmpty(iv))
            throw new ArgumentException("IV cannot be null or empty", nameof(iv));

        _key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32)); // Ensure 32 bytes for AES-256
        _iv = Encoding.UTF8.GetBytes(iv.PadRight(16).Substring(0, 16));   // Ensure 16 bytes for IV
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] encryptedBytes = Encrypt(plainBytes);
        return Convert.ToBase64String(encryptedBytes);
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        byte[] cipherBytes = Convert.FromBase64String(cipherText);
        byte[] decryptedBytes = Decrypt(cipherBytes);
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    public byte[] Encrypt(byte[] plainBytes)
    {
        if (plainBytes == null || plainBytes.Length == 0)
            return Array.Empty<byte>();

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        using var msEncrypt = new MemoryStream();
        using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        
        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
        csEncrypt.FlushFinalBlock();
        
        return msEncrypt.ToArray();
    }

    public byte[] Decrypt(byte[] cipherBytes)
    {
        if (cipherBytes == null || cipherBytes.Length == 0)
            return Array.Empty<byte>();

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        using var msDecrypt = new MemoryStream(cipherBytes);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var msResult = new MemoryStream();
        
        csDecrypt.CopyTo(msResult);
        return msResult.ToArray();
    }

    public string EncryptToBase64(string plainText)
    {
        return Encrypt(plainText);
    }

    public string DecryptFromBase64(string base64CipherText)
    {
        return Decrypt(base64CipherText);
    }
}
