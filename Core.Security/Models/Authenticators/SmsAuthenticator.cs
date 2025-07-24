using ZCode.Core.Domain.Entities;

namespace NArchitecture.Core.Security.Entities;

public class SmsAuthenticator<TUserId> : Entity<TUserId>
{
    public TUserId UserId { get; set; }
    public string? PhoneNumber { get; set; }
    public string? ActivationCode { get; set; }
    public DateTime? CodeCreatedAt { get; set; }
    public DateTime? VerifiedAt { get; set; }
    public bool IsVerified { get; set; }

    public SmsAuthenticator()
    {
        UserId = default!;
    }

    public SmsAuthenticator(TUserId userId, string phoneNumber, bool isVerified)
    {
        UserId = userId;
        PhoneNumber = phoneNumber;
        IsVerified = isVerified;
    }

    public SmsAuthenticator(TUserId id, TUserId userId, string phoneNumber, bool isVerified)
        : base(id)
    {
        UserId = userId;
        PhoneNumber = phoneNumber;
        IsVerified = isVerified;
    }

    public void SetActivationCode(string code)
    {
        ActivationCode = code;
        CodeCreatedAt = DateTime.UtcNow;
        IsVerified = false;
    }

    public void VerifyCode()
    {
        IsVerified = true;
        VerifiedAt = DateTime.UtcNow;
    }
}
