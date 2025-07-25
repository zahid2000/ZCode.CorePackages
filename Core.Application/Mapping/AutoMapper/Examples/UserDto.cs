using AutoMapper;
using ZCode.Core.Application.Mapping.AutoMapper.Models;
using ZCode.Core.Domain.ValueObjects;

namespace ZCode.Core.Application.Mapping.AutoMapper.Examples;

// Example DTO that implements IMapFrom pattern
public class UserDto : IMapFrom<User>
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public DateTime CreatedDate { get; set; }

    // Custom mapping configuration
    public void Mapping(Profile profile)
    {
        profile.CreateMap<User, UserDto>()
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email.Value))
            .ForMember(dest => dest.FullName, opt => opt.MapFrom(src => $"{src.FirstName} {src.LastName}"));
    }
}

// Example entity for demonstration
public class User
{
    public Guid Id { get; set; }
    public Email Email { get; set; } = null!;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public DateTime CreatedDate { get; set; }
}
