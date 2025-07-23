using MediatR;

namespace ZCode.Core.Domain.Events;

public interface IDomainEvent : INotification
{
    DateTime OccurredOn { get; }
}

public interface IPreSaveDomainEvent : IDomainEvent
{
    // Events that should be published before SaveChanges
}

public interface IPostSaveDomainEvent : IDomainEvent
{
    // Events that should be published after SaveChanges
}
