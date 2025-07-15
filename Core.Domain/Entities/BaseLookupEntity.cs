using ZCode.Core.Domain.Entities;

namespace Domain.Entities.BaseEntities;

public class BaseLookupEntity<TId> : Entity<TId>
{
    public string Name { get; set; }
}