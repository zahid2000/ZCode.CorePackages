using Mapster;
using ZCode.Core.Application.Mapping.Mapster.Models;
using EmailObj= ZCode.Core.Domain.ValueObjects.Email;

namespace ZCode.Core.Application.Mapping.Mapster.Examples;

// Example command that implements IMapsterTo pattern
public class CreateUserMapsterCommand : IMapsterTo<User>
{
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;

    // Custom mapping configuration
    public void Mapping(TypeAdapterConfig config)
    {
        config.NewConfig<CreateUserMapsterCommand, User>()
            .Map(dest => dest.Id, src => Guid.NewGuid())
            .Map(dest => dest.Email, src => EmailObj.Create(src.Email))
            .Map(dest => dest.CreatedDate, src => DateTime.UtcNow);
    }
}
