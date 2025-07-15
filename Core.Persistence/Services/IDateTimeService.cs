namespace ZCode.Core.Persistence.Services;

public interface IDateTimeService
{
    DateTimeOffset Now { get; }
    DateTimeOffset UtcNow { get; }
}
