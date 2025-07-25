using AutoMapper;
using ZCode.Core.Application.Mapping.AutoMapper.Models;
using EmailObj= ZCode.Core.Domain.ValueObjects.Email;
namespace ZCode.Core.Application.Mapping.AutoMapper.Examples;

// Example command that implements IMapTo pattern
public class CreateUserCommand : IMapTo<User>
{
    public string Email { get; set; } =default!;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;

    // Custom mapping configuration
    public void Mapping(Profile profile)
    {
        profile.CreateMap<CreateUserCommand, User>()
            .ForMember(dest => dest.Id, opt => opt.MapFrom(src => Guid.NewGuid()))
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => EmailObj.Create(src.Email)))
            .ForMember(dest => dest.CreatedDate, opt => opt.MapFrom(src => DateTime.UtcNow));
    }
}
