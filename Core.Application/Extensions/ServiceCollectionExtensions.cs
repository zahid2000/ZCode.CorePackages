using System.Reflection;
using FluentValidation;
using FluentValidation.AspNetCore;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using ZCode.Core.Application.Events;
using ZCode.Core.Application.Pipelines.Caching;
using ZCode.Core.Application.Pipelines.Logging;
using ZCode.Core.Application.Pipelines.Performance;
using ZCode.Core.Application.Pipelines.Transaction;
using ZCode.Core.Application.Pipelines.Validation;

namespace ZCode.Core.Application.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services, Assembly assembly)
    {
        services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(assembly));
        services.AddValidatorsFromAssembly(assembly);

        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(RequestValidationBehavior<,>));
        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(TransactionScopeBehavior<,>));
        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(CachingBehavior<,>));
        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(CacheRemovingBehavior<,>));
        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(PerformanceBehavior<,>));

        // Register domain event publisher
        services.AddScoped<IDomainEventPublisher, DomainEventPublisher>();

        return services;
    }
}
