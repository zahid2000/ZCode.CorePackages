using System.Reflection;
using AutoMapper;
using FluentValidation;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using ZCode.Core.Application.Events;
using ZCode.Core.Application.Mapping.AutoMapper.Profiles;
using ZCode.Core.Application.Mapping.AutoMapper.Services;
using ZCode.Core.Application.Mapping.Mapster.Configuration;
using ZCode.Core.Application.Mapping.Mapster.Services;
using ZCode.Core.Application.Mapping.Services;
using Mapster;
using ZCode.Core.Application.Pipelines.Caching;
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

    public static IServiceCollection AddAutoMapperServices(this IServiceCollection services, Action<IMapperConfigurationExpression>? configuration = null, params Assembly[] assemblies)
    {
        if (assemblies?.Length > 0)
        {
            // Use provided assemblies with MappingProfile
            services.AddAutoMapper(cfg =>
            {
                cfg.AddProfile(new MappingProfile(assemblies));
                configuration?.Invoke(cfg);
            });
        }
        else
        {
            // Use executing assembly with MappingProfile
            services.AddAutoMapper(cfg =>
            {
                cfg.AddProfile<MappingProfile>();
                configuration?.Invoke(cfg);
            });
        }

        // Register AutoMapper service as both regular and keyed service
        services.AddScoped<IMapperService, AutoMapperService>();
        services.AddKeyedScoped<IMapperService, AutoMapperService>("AutoMapper");

        return services;
    }

    public static IServiceCollection AddAutoMapperServices(this IServiceCollection services, params Assembly[] assemblies)
    {
        return services.AddAutoMapperServices(null, assemblies);
    }

    public static IServiceCollection AddMapsterServices(this IServiceCollection services, params Assembly[] assemblies)
    {
        // Create Mapster configuration
        var config = assemblies?.Length > 0
            ? MapsterConfiguration.CreateConfiguration(assemblies)
            : MapsterConfiguration.CreateConfiguration();

        // Register configuration as singleton
        services.AddSingleton(config);

        // Register Mapster service as both regular and keyed service
        services.AddScoped<IMapperService, MapsterService>();
        services.AddKeyedScoped<IMapperService, MapsterService>("Mapster");

        return services;
    }

    public static IServiceCollection AddMappingStrategySelector(this IServiceCollection services)
    {
        services.AddScoped<IMappingStrategySelector, MappingStrategySelector>();
        return services;
    }

    public static IServiceCollection AddBothMappingServices(this IServiceCollection services, params Assembly[] assemblies)
    {
        // Add both AutoMapper and Mapster
        services.AddAutoMapperServices(assemblies);
        services.AddMapsterServices(assemblies);

        // Add strategy selector
        services.AddMappingStrategySelector();

        return services;
    }
}
