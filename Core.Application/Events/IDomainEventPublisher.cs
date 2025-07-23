using ZCode.Core.Domain.Events;

namespace ZCode.Core.Application.Events;

public interface IDomainEventPublisher
{
    Task PublishAsync<T>(T domainEvent, CancellationToken cancellationToken = default) where T : IDomainEvent;
    Task PublishAsync(IDomainEvent domainEvent, CancellationToken cancellationToken = default);
    
    // For nested events - queues events to be published after current event processing
    Task QueueEventAsync<T>(T domainEvent, CancellationToken cancellationToken = default) where T : IDomainEvent;
    Task QueueEventAsync(IDomainEvent domainEvent, CancellationToken cancellationToken = default);
    
    // Process all queued events
    Task ProcessQueuedEventsAsync(CancellationToken cancellationToken = default);
}
