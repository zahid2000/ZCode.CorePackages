using Mapster;

namespace ZCode.Core.Application.Mapping.Mapster.Models;

/// <summary>
/// Interface for objects that can be mapped to another type using Mapster
/// </summary>
/// <typeparam name="T">Destination type to map to</typeparam>
public interface IMapsterTo<T>
{
    /// <summary>
    /// Configure mapping to destination type
    /// </summary>
    /// <param name="config">Mapster type adapter config</param>
    void Mapping(TypeAdapterConfig config) => config.NewConfig(GetType(), typeof(T));
}
