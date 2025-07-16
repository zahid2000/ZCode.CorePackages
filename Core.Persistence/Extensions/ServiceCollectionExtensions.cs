using Microsoft.Extensions.DependencyInjection;
using System.Reflection;

namespace ZCode.Core.Persistence.Extensions;


public static class ServiceCollectionExtensions
{
    public static void RegisterAllRepositories(this IServiceCollection services, Assembly assembly, Type baseInterface = null)
    {
        var types = assembly.GetTypes();

        var interfaces = types.Where(t => t.IsInterface && t.Name.EndsWith("Repository"));
        var implementations = types.Where(t => t.IsClass && !t.IsAbstract && t.Name.EndsWith("Repository"));

        foreach (var @interface in interfaces)
        {
            var implementation = implementations.FirstOrDefault(x => @interface.IsAssignableFrom(x));
            if (implementation != null)
            {
                services.AddScoped(@interface, implementation);
            }
        }

        // Optional: register generic IRepository<T> to Repository<T> if needed
        if (baseInterface != null && baseInterface.IsGenericTypeDefinition)
        {
            foreach (var impl in implementations)
            {
                var repoInterface = impl.GetInterfaces().FirstOrDefault(i =>
                    i.IsGenericType &&
                    i.GetGenericTypeDefinition() == baseInterface);

                if (repoInterface != null)
                {
                    services.AddScoped(repoInterface, impl);
                }
            }
        }
    }
}