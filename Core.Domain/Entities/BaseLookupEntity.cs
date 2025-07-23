using ZCode.Core.Domain.Entities;

namespace ZCode.Core.Domain.Entities;

public class BaseLookupEntity<TId> : Entity<TId>
{
    public string Name { get; set; }

    public BaseLookupEntity()
    {
        Name = string.Empty;
    }

    public BaseLookupEntity(TId id, string name) : base(id)
    {
        Name = name;
    }
}