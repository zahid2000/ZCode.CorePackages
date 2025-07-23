using Hangfire;
using System.Linq.Expressions;
using ZCode.Core.BackgroundJobs.Abstractions;

namespace ZCode.Core.BackgroundJobs.Services;

public class HangfireBackgroundJobService : IBackgroundJobService
{
    public string Enqueue(Expression<Action> methodCall)
    {
        return BackgroundJob.Enqueue(methodCall);
    }

    public string Enqueue<T>(Expression<Action<T>> methodCall)
    {
        return BackgroundJob.Enqueue<T>(methodCall);
    }

    public string Schedule(Expression<Action> methodCall, TimeSpan delay)
    {
        return BackgroundJob.Schedule(methodCall, delay);
    }

    public string Schedule<T>(Expression<Action<T>> methodCall, TimeSpan delay)
    {
        return BackgroundJob.Schedule<T>(methodCall, delay);
    }

    public string Schedule(Expression<Action> methodCall, DateTimeOffset enqueueAt)
    {
        return BackgroundJob.Schedule(methodCall, enqueueAt);
    }

    public string Schedule<T>(Expression<Action<T>> methodCall, DateTimeOffset enqueueAt)
    {
        return BackgroundJob.Schedule<T>(methodCall, enqueueAt);
    }

    public void AddOrUpdateRecurringJob(string jobId, Expression<Action> methodCall, string cronExpression)
    {
        RecurringJob.AddOrUpdate(jobId, methodCall, cronExpression);
    }

    public void AddOrUpdateRecurringJob<T>(string jobId, Expression<Action<T>> methodCall, string cronExpression)
    {
        RecurringJob.AddOrUpdate<T>(jobId, methodCall, cronExpression);
    }

    public void RemoveRecurringJob(string jobId)
    {
        RecurringJob.RemoveIfExists(jobId);
    }

    public bool Delete(string jobId)
    {
        return BackgroundJob.Delete(jobId);
    }

    public bool Requeue(string jobId)
    {
        return BackgroundJob.Requeue(jobId);
    }
}
