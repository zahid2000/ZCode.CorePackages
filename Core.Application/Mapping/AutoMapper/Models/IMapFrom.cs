using AutoMapper;

namespace ZCode.Core.Application.Mapping.AutoMapper.Models;

/// <summary>
/// Interface for objects that can be mapped from another type
/// </summary>
/// <typeparam name="T">Source type to map from</typeparam>
public interface IMapFrom<T>
{
    /// <summary>
    /// Configure mapping from source type
    /// </summary>
    /// <param name="profile">AutoMapper profile</param>
    void Mapping(Profile profile) => profile.CreateMap(typeof(T), GetType());
}
