using BCrypt.Net;

namespace ZCode.Core.Security.Hashing;

public class BCryptHashingService : IHashingService
{
    private readonly int _workFactor;

    public BCryptHashingService(int workFactor = 12)
    {
        _workFactor = workFactor;
    }

    public string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, _workFactor);
    }

    public bool VerifyPassword(string password, string hashedPassword)
    {
        return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
    }

    public string GenerateSalt()
    {
        return BCrypt.Net.BCrypt.GenerateSalt(_workFactor);
    }

    public string HashWithSalt(string input, string salt)
    {
        return BCrypt.Net.BCrypt.HashPassword(input, salt);
    }
}
