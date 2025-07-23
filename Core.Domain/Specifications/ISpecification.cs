using System.Linq.Expressions;

namespace ZCode.Core.Domain.Specifications;

public interface ISpecification<T>
{
    Expression<Func<T, bool>> ToExpression();
    bool IsSatisfiedBy(T entity);
}
