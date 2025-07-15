namespace ZCode.Core.Domain.Entities;

public interface IEntity<T>
{
    T Id { get; set; }
}
