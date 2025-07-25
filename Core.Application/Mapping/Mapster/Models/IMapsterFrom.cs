using Mapster;

namespace ZCode.Core.Application.Mapping.Mapster.Models;

/// <summary>
/// Interface for objects that can be mapped from another type using Mapster
/// </summary>
/// <typeparam name="T">Source type to map from</typeparam>
public interface IMapsterFrom<T>
{
    /// <summary>
    /// Configure mapping from source type
    /// </summary>
    /// <param name="config">Mapster type adapter config</param>
    void Mapping(TypeAdapterConfig config) => config.NewConfig(typeof(T), GetType());
}
