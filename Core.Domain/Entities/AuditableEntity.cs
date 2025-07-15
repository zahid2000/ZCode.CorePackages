using ZCode.Core.Domain.Entities;

namespace ZCode.Core.Domain.Entities;

public class AuditableEntity<TId> : Entity<TId>
{
    public TId CreatedBy { get; set; }
    public TId? LastModifiedBy { get; set; }
    public TId? DeletedBy { get; set; }
}
