using System.Linq.Expressions;

namespace ZCode.Core.BackgroundJobs.Abstractions;

public interface IBackgroundJobService
{
    // Fire and forget
    string Enqueue(Expression<Action> methodCall);
    string Enqueue<T>(Expression<Action<T>> methodCall);
    
    // Delayed execution
    string Schedule(Expression<Action> methodCall, TimeSpan delay);
    string Schedule<T>(Expression<Action<T>> methodCall, TimeSpan delay);
    string Schedule(Expression<Action> methodCall, DateTimeOffset enqueueAt);
    string Schedule<T>(Expression<Action<T>> methodCall, DateTimeOffset enqueueAt);
    
    // Recurring jobs
    void AddOrUpdateRecurringJob(string jobId, Expression<Action> methodCall, string cronExpression);
    void AddOrUpdateRecurringJob<T>(string jobId, Expression<Action<T>> methodCall, string cronExpression);
    void RemoveRecurringJob(string jobId);
    
    // Job management
    bool Delete(string jobId);
    bool Requeue(string jobId);
}
