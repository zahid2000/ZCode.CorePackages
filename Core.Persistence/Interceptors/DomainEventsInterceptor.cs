using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;
using ZCode.Core.Domain.Entities;
using ZCode.Core.Domain.Events;

namespace ZCode.Core.Persistence.Interceptors;

public class DomainEventsInterceptor : SaveChangesInterceptor
{
    private readonly IMediator _mediator;
    private readonly ILogger<DomainEventsInterceptor> _logger;
    private readonly List<IDomainEvent> _postSaveEvents = new();

    public DomainEventsInterceptor(IMediator mediator, ILogger<DomainEventsInterceptor> logger)
    {
        _mediator = mediator;
        _logger = logger;
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        PublishPreSaveEvents(eventData.Context).GetAwaiter().GetResult();
        return base.SavingChanges(eventData, result);
    }

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        await PublishPreSaveEvents(eventData.Context);
        return await base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        PublishPostSaveEvents().GetAwaiter().GetResult();
        return base.SavedChanges(eventData, result);
    }

    public override async ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData,
        int result,
        CancellationToken cancellationToken = default)
    {
        await PublishPostSaveEvents();
        return await base.SavedChangesAsync(eventData, result, cancellationToken);
    }

    private async Task PublishPreSaveEvents(DbContext? context)
    {
        if (context == null) return;

        var entitiesWithEvents = context.ChangeTracker
            .Entries<IHasDomainEvents>()
            .Where(x => x.Entity.DomainEvents.Any())
            .Select(x => x.Entity)
            .ToList();

        var allEvents = entitiesWithEvents
            .SelectMany(x => x.DomainEvents)
            .ToList();

        var preSaveEvents = allEvents.OfType<IPreSaveDomainEvent>().ToList();
        var postSaveEvents = allEvents.OfType<IPostSaveDomainEvent>().ToList();

        // Store post-save events for later
        _postSaveEvents.AddRange(postSaveEvents);

        // Clear all events from entities
        entitiesWithEvents.ForEach(entity => entity.ClearDomainEvents());

        // Publish pre-save events
        foreach (var domainEvent in preSaveEvents)
        {
            try
            {
                _logger.LogDebug("Publishing pre-save domain event: {EventType}", domainEvent.GetType().Name);
                await _mediator.Publish(domainEvent);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error publishing pre-save domain event: {EventType}", domainEvent.GetType().Name);
                throw;
            }
        }
    }

    private async Task PublishPostSaveEvents()
    {
        var eventsToPublish = _postSaveEvents.ToList();
        _postSaveEvents.Clear();

        foreach (var domainEvent in eventsToPublish)
        {
            try
            {
                _logger.LogDebug("Publishing post-save domain event: {EventType}", domainEvent.GetType().Name);
                await _mediator.Publish(domainEvent);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error publishing post-save domain event: {EventType}", domainEvent.GetType().Name);
                // Post-save events should not break the flow, just log the error
            }
        }
    }
}
