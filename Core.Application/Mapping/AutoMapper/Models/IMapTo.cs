using AutoMapper;

namespace ZCode.Core.Application.Mapping.AutoMapper.Models;

/// <summary>
/// Interface for objects that can be mapped to another type
/// </summary>
/// <typeparam name="T">Destination type to map to</typeparam>
public interface IMapTo<T>
{
    /// <summary>
    /// Configure mapping to destination type
    /// </summary>
    /// <param name="profile">AutoMapper profile</param>
    void Mapping(Profile profile) => profile.CreateMap(GetType(), typeof(T));
}
