namespace ZCode.Core.Security.Encrypting;

public interface IEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
    byte[] Encrypt(byte[] plainBytes);
    byte[] Decrypt(byte[] cipherBytes);
    string EncryptToBase64(string plainText);
    string DecryptFromBase64(string base64CipherText);
}
