using Mapster;
using System.Reflection;
using ZCode.Core.Application.Mapping.Mapster.Models;

namespace ZCode.Core.Application.Mapping.Mapster.Configuration;

/// <summary>
/// Mapster configuration that automatically configures mappings for IMapsterFrom and IMapsterTo implementations
/// </summary>
public static class MapsterConfiguration
{
    public static TypeAdapterConfig CreateConfiguration()
    {
        var config = new TypeAdapterConfig();
        ApplyMappingsFromAssembly(config, Assembly.GetExecutingAssembly());
        return config;
    }

    public static TypeAdapterConfig CreateConfiguration(Assembly assembly)
    {
        var config = new TypeAdapterConfig();
        ApplyMappingsFromAssembly(config, assembly);
        return config;
    }

    public static TypeAdapterConfig CreateConfiguration(params Assembly[] assemblies)
    {
        var config = new TypeAdapterConfig();
        foreach (var assembly in assemblies)
        {
            ApplyMappingsFromAssembly(config, assembly);
        }
        return config;
    }

    private static void ApplyMappingsFromAssembly(TypeAdapterConfig config, Assembly assembly)
    {
        var mapFromType = typeof(IMapsterFrom<>);
        var mapToType = typeof(IMapsterTo<>);

        // Get all types that implement IMapsterFrom<T>
        var mapFromTypes = assembly.GetExportedTypes()
            .Where(t => t.GetInterfaces().Any(i => 
                i.IsGenericType && i.GetGenericTypeDefinition() == mapFromType))
            .ToList();

        foreach (var type in mapFromTypes)
        {
            var instance = Activator.CreateInstance(type);
            var methodInfo = type.GetMethod("Mapping") 
                ?? type.GetInterface("IMapsterFrom`1")?.GetMethod("Mapping");

            methodInfo?.Invoke(instance, new object[] { config });
        }

        // Get all types that implement IMapsterTo<T>
        var mapToTypes = assembly.GetExportedTypes()
            .Where(t => t.GetInterfaces().Any(i => 
                i.IsGenericType && i.GetGenericTypeDefinition() == mapToType))
            .ToList();

        foreach (var type in mapToTypes)
        {
            var instance = Activator.CreateInstance(type);
            var methodInfo = type.GetMethod("Mapping") 
                ?? type.GetInterface("IMapsterTo`1")?.GetMethod("Mapping");

            methodInfo?.Invoke(instance, new object[] { config });
        }
    }
}
