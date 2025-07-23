using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ZCode.Core.Testing.Database;

public static class InMemoryDbContextFactory
{
    public static TContext Create<TContext>(string? databaseName = null) 
        where TContext : DbContext
    {
        var services = new ServiceCollection();
        
        services.AddDbContext<TContext>(options =>
            options.UseInMemoryDatabase(databaseName ?? Guid.NewGuid().ToString())
                   .EnableSensitiveDataLogging()
                   .UseLoggerFactory(LoggerFactory.Create(builder => builder.AddConsole())));

        var serviceProvider = services.BuildServiceProvider();
        var context = serviceProvider.GetRequiredService<TContext>();
        
        context.Database.EnsureCreated();
        return context;
    }

    public static TContext CreateWithData<TContext>(Action<TContext> seedData, string? databaseName = null)
        where TContext : DbContext
    {
        var context = Create<TContext>(databaseName);
        seedData(context);
        context.SaveChanges();
        return context;
    }
}
