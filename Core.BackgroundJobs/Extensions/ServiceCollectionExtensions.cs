using Hangfire;
using Hangfire.SqlServer;
using Microsoft.Extensions.DependencyInjection;
using ZCode.Core.BackgroundJobs.Abstractions;
using ZCode.Core.BackgroundJobs.Services;

namespace ZCode.Core.BackgroundJobs.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddBackgroundJobs(this IServiceCollection services, string connectionString)
    {
        services.AddHangfire(configuration => configuration
            .SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
            .UseSimpleAssemblyNameTypeSerializer()
            .UseRecommendedSerializerSettings()
            .UseSqlServerStorage(connectionString, new SqlServerStorageOptions
            {
                CommandBatchMaxTimeout = TimeSpan.FromMinutes(5),
                SlidingInvisibilityTimeout = TimeSpan.FromMinutes(5),
                QueuePollInterval = TimeSpan.Zero,
                UseRecommendedIsolationLevel = true,
                DisableGlobalLocks = true
            }));

        services.AddHangfireServer();
        services.AddScoped<IBackgroundJobService, HangfireBackgroundJobService>();

        return services;
    }
}
