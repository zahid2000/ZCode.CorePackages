using AutoFixture;
using ZCode.Core.Domain.Entities;

namespace ZCode.Core.Testing.Builders;

public abstract class EntityBuilder<TEntity, TId, TBuilder>
    where TEntity : Entity<TId>
    where TBuilder : EntityBuilder<TEntity, TId, TBuilder>
{
    protected readonly Fixture _fixture;
    protected TEntity _entity;

    protected EntityBuilder()
    {
        _fixture = new Fixture();
        _entity = CreateEntity();
    }

    protected abstract TEntity CreateEntity();

    public TBuilder WithId(TId id)
    {
        _entity.Id = id;
        return (TBuilder)this;
    }

    public TBuilder WithCreatedDate(DateTime createdDate)
    {
        _entity.CreatedDate = createdDate;
        return (TBuilder)this;
    }

    public TBuilder WithUpdatedDate(DateTime? updatedDate)
    {
        _entity.UpdatedDate = updatedDate;
        return (TBuilder)this;
    }

    public TBuilder WithDeletedDate(DateTime? deletedDate)
    {
        _entity.DeletedDate = deletedDate;
        return (TBuilder)this;
    }

    public TEntity Build() => _entity;

    public static implicit operator TEntity(EntityBuilder<TEntity, TId, TBuilder> builder)
        => builder.Build();
}
