using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;
using System.Reflection;
using ZCode.Core.Domain.Entities;

namespace ZCode.Core.Persistence.Extensions;

public static class ModelBuilderExtensions
{
    public static void RegisterAllEntities<TInterface>(this ModelBuilder modelBuilder, Assembly assembly)
    {
        var entityTypes = assembly.GetTypes()
            .Where(t => t.IsClass && !t.IsAbstract && typeof(TInterface).IsAssignableFrom(t));

        foreach (var type in entityTypes)
        {
            modelBuilder.Entity(type);
        }
    }

    public static void ApplySoftDeleteQueryFilter(this ModelBuilder modelBuilder)
    {
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            if (typeof(IEntityTimestamps).IsAssignableFrom(entityType.ClrType))
            {
                var parameter = Expression.Parameter(entityType.ClrType, "e");
                var property = Expression.Property(parameter, nameof(IEntityTimestamps.DeletedDate));
                var condition = Expression.Equal(property, Expression.Constant(null));
                var lambda = Expression.Lambda(condition, parameter);

                modelBuilder.Entity(entityType.ClrType).HasQueryFilter(lambda);
            }
        }
    }
}
