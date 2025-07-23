namespace ZCode.Core.Security.Hashing;

public interface IHashingService
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hashedPassword);
    string GenerateSalt();
    string HashWithSalt(string input, string salt);
}
