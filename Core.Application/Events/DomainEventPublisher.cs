using MediatR;
using Microsoft.Extensions.Logging;
using ZCode.Core.Domain.Events;

namespace ZCode.Core.Application.Events;

public class DomainEventPublisher : IDomainEventPublisher
{
    private readonly IMediator _mediator;
    private readonly ILogger<DomainEventPublisher> _logger;
    private readonly Queue<IDomainEvent> _eventQueue = new();
    private bool _isProcessingQueue = false;

    public DomainEventPublisher(IMediator mediator, ILogger<DomainEventPublisher> logger)
    {
        _mediator = mediator;
        _logger = logger;
    }

    public async Task PublishAsync<T>(T domainEvent, CancellationToken cancellationToken = default) where T : IDomainEvent
    {
        await PublishAsync((IDomainEvent)domainEvent, cancellationToken);
    }

    public async Task PublishAsync(IDomainEvent domainEvent, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Publishing domain event: {EventType}", domainEvent.GetType().Name);
            await _mediator.Publish(domainEvent, cancellationToken);
            
            // Process any queued events after publishing current event
            if (!_isProcessingQueue)
            {
                await ProcessQueuedEventsAsync(cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error publishing domain event: {EventType}", domainEvent.GetType().Name);
            throw;
        }
    }

    public async Task QueueEventAsync<T>(T domainEvent, CancellationToken cancellationToken = default) where T : IDomainEvent
    {
        await QueueEventAsync((IDomainEvent)domainEvent, cancellationToken);
    }

    public Task QueueEventAsync(IDomainEvent domainEvent, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Queueing domain event: {EventType}", domainEvent.GetType().Name);
        _eventQueue.Enqueue(domainEvent);
        return Task.CompletedTask;
    }

    public async Task ProcessQueuedEventsAsync(CancellationToken cancellationToken = default)
    {
        if (_isProcessingQueue) return; // Prevent infinite recursion

        _isProcessingQueue = true;
        
        try
        {
            while (_eventQueue.Count > 0)
            {
                var queuedEvent = _eventQueue.Dequeue();
                
                try
                {
                    _logger.LogDebug("Processing queued domain event: {EventType}", queuedEvent.GetType().Name);
                    await _mediator.Publish(queuedEvent, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing queued domain event: {EventType}", queuedEvent.GetType().Name);
                    // Continue processing other events
                }
            }
        }
        finally
        {
            _isProcessingQueue = false;
        }
    }
}
