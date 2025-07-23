namespace ZCode.Core.Domain.Events.Examples;

// Pre-save event - will be published before SaveChanges
public class UserCreatedEvent : DomainEvent, IPreSaveDomainEvent
{
    public Guid UserId { get; }
    public string Email { get; }

    public UserCreatedEvent(Guid userId, string email)
    {
        UserId = userId;
        Email = email;
    }
}

// Post-save event - will be published after SaveChanges
public class UserPersistedEvent : DomainEvent, IPostSaveDomainEvent
{
    public Guid UserId { get; }
    public string Email { get; }

    public UserPersistedEvent(Guid userId, string email)
    {
        UserId = userId;
        Email = email;
    }
}
