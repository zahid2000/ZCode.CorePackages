namespace ZCode.Core.Persistence.Services;

public class DateTimeService : IDateTimeService
{
    public DateTimeOffset Now { get => DateTimeOffset.Now; }
    public DateTimeOffset UtcNow { get => DateTimeOffset.UtcNow; }
}
