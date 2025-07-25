using AutoMapper;
using System.Reflection;
using ZCode.Core.Application.Mapping.AutoMapper.Models;

namespace ZCode.Core.Application.Mapping.AutoMapper.Profiles;

/// <summary>
/// AutoMapper profile that automatically configures mappings for IMapFrom and IMapTo implementations
/// </summary>
public class MappingProfile : Profile
{
    public MappingProfile()
    {
        ApplyMappingsFromAssembly(Assembly.GetExecutingAssembly());
    }

    public MappingProfile(Assembly assembly)
    {
        ApplyMappingsFromAssembly(assembly);
    }

    public MappingProfile(params Assembly[] assemblies)
    {
        foreach (var assembly in assemblies)
        {
            ApplyMappingsFromAssembly(assembly);
        }
    }

    private void ApplyMappingsFromAssembly(Assembly assembly)
    {
        var mapFromType = typeof(IMapFrom<>);
        var mapToType = typeof(IMapTo<>);

        // Get all types that implement IMapFrom<T>
        var mapFromTypes = assembly.GetExportedTypes()
            .Where(t => t.GetInterfaces().Any(i => 
                i.IsGenericType && i.GetGenericTypeDefinition() == mapFromType))
            .ToList();

        foreach (var type in mapFromTypes)
        {
            var instance = Activator.CreateInstance(type);
            var methodInfo = type.GetMethod("Mapping") 
                ?? type.GetInterface("IMapFrom`1")?.GetMethod("Mapping");

            methodInfo?.Invoke(instance, new object[] { this });
        }

        // Get all types that implement IMapTo<T>
        var mapToTypes = assembly.GetExportedTypes()
            .Where(t => t.GetInterfaces().Any(i => 
                i.IsGenericType && i.GetGenericTypeDefinition() == mapToType))
            .ToList();

        foreach (var type in mapToTypes)
        {
            var instance = Activator.CreateInstance(type);
            var methodInfo = type.GetMethod("Mapping") 
                ?? type.GetInterface("IMapTo`1")?.GetMethod("Mapping");

            methodInfo?.Invoke(instance, new object[] { this });
        }
    }
}
