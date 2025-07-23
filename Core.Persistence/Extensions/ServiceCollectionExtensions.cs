using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using System.Reflection;
using ZCode.Core.Persistence.Interceptors;
using ZCode.Core.Persistence.Services;
using ZCode.Core.Persistence.UnitOfWork;
namespace ZCode.Core.Persistence.Extensions;

/// <summary>
/// Represents the lifetime scope of a dependency injection registration.
/// </summary>
public enum LifeCycle
{
    /// <summary>
    /// A single instance is created and shared for the application's lifetime.
    /// </summary>
    Singleton,

    /// <summary>
    /// A new instance is created per HTTP request or scope.
    /// </summary>
    Scoped,

    /// <summary>
    /// A new instance is created each time it is requested.
    /// </summary>
    Transient
}

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all non-abstract classes from the given assembly whose names end with the specified suffix.
    /// If a matching interface (by name) is found, registers the class as that interface.
    /// If no interface is found, registers the class itself.
    /// </summary>
    /// <param name="services">The service collection to register into (IServiceCollection).</param>
    /// <param name="assembly">The assembly to scan for classes.</param>
    /// <param name="suffix">The suffix used to filter class and interface names (e.g., "Service", "Repository").</param>
    /// <param name="lifeCycle">The desired DI lifetime (Scoped, Singleton, Transient).</param>

    public static void RegisterBySuffix(
        this IServiceCollection services,
        Assembly assembly,
        string suffix,
        LifeCycle lifeCycle = LifeCycle.Scoped)
    {
        var types = assembly.GetTypes();

        // Suffix-ə uyğun, abstract olmayan class-ları tapırıq
        var classTypes = types
            .Where(t => t.IsClass
                     && !t.IsAbstract
                     && t.Name.ToUpperInvariant()
                               .EndsWith(suffix.ToUpperInvariant())
                  )
            .ToList();

        foreach (var implementation in classTypes)
        {
            // Həmin class-ın suffix-lə bitən interfeysini axtarırıq (əgər varsa)
            var interfaceType = implementation.GetInterfaces()
                .FirstOrDefault(i => i.Name.ToUpperInvariant().EndsWith(suffix.ToUpperInvariant()) && i.IsPublic);

            // Əgər interface varsa → interface ilə register et
            // Interface yoxdursa → özünü özünə register et
            if (interfaceType != null)
                Register(services, interfaceType, implementation, lifeCycle);
            else
                Register(services, implementation, implementation, lifeCycle);
        }
    }

    /// <summary>
    /// Registers the implementation type into the service collection with the specified lifetime.
    /// If the serviceType is equal to the implementationType, registers the type as itself (no interface).
    /// </summary>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="serviceType">The interface or service type to register.</param>
    /// <param name="implementationType">The concrete class that implements the service.</param>
    /// <param name="lifeCycle">The desired DI lifetime.</param>

    private static void Register(IServiceCollection services, Type serviceType, Type implementationType, LifeCycle lifeCycle)
    {
        switch (lifeCycle)
        {
            case LifeCycle.Singleton:
                services.AddSingleton(serviceType, implementationType);
                break;
            case LifeCycle.Scoped:
                services.AddScoped(serviceType, implementationType);
                break;
            case LifeCycle.Transient:
                services.AddTransient(serviceType, implementationType);
                break;
        }
    }

    public static IServiceCollection AddPersistenceServices<TContext>(this IServiceCollection services)
        where TContext : DbContext
    {
        services.AddScoped<IDateTimeService, DateTimeService>();
        services.AddScoped<IUnitOfWork, UnitOfWork<TContext>>();
        services.AddScoped<DomainEventsInterceptor>();
        services.AddScoped<AuditableEntitySaveChangesInterceptors<Guid>>();

        return services;
    }
}
