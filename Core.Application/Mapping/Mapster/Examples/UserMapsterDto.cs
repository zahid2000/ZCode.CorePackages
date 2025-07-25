using Mapster;
using ZCode.Core.Application.Mapping.Mapster.Models;
using ZCode.Core.Domain.ValueObjects;

namespace ZCode.Core.Application.Mapping.Mapster.Examples;

// Example DTO that implements IMapsterFrom pattern
public class UserMapsterDto : IMapsterFrom<User>
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public DateTime CreatedDate { get; set; }

    // Custom mapping configuration
    public void Mapping(TypeAdapterConfig config)
    {
        config.NewConfig<User, UserMapsterDto>()
            .Map(dest => dest.Email, src => src.Email.Value)
            .Map(dest => dest.FullName, src => $"{src.FirstName} {src.LastName}");
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
