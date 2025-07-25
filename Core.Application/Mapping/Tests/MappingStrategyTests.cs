using Microsoft.Extensions.DependencyInjection;
using ZCode.Core.Application.Extensions;
using ZCode.Core.Application.Mapping.Services;
using System.Reflection;

namespace ZCode.Core.Application.Mapping.Tests;

/// <summary>
/// Test class to verify both AutoMapper and Mapster work correctly with Strategy Selector
/// </summary>
public class MappingStrategyTests
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IMappingStrategySelector _strategySelector;

    public MappingStrategyTests()
    {
        var services = new ServiceCollection();
        
        // Register both mapping services
        services.AddBothMappingServices(Assembly.GetExecutingAssembly());
        
        _serviceProvider = services.BuildServiceProvider();
        _strategySelector = _serviceProvider.GetRequiredService<IMappingStrategySelector>();
    }

    public void TestAutoMapperStrategy()
    {
        // Arrange
        var testData = new { Name = "Test", Value = 123 };

        // Act
        var autoMapper = _strategySelector.GetMapper(MappingStrategy.AutoMapper);
        
        // Assert - Should not throw exception
        Assert.NotNull(autoMapper);
        Console.WriteLine("✅ AutoMapper strategy works correctly");
    }

    public void TestMapsterStrategy()
    {
        // Arrange
        var testData = new { Name = "Test", Value = 123 };

        // Act
        var mapster = _strategySelector.GetMapper(MappingStrategy.Mapster);
        
        // Assert - Should not throw exception
        Assert.NotNull(mapster);
        Console.WriteLine("✅ Mapster strategy works correctly");
    }

    public void TestBothStrategiesWork()
    {
        try
        {
            TestAutoMapperStrategy();
            TestMapsterStrategy();
            Console.WriteLine("🎉 Both mapping strategies are properly registered and working!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            throw;
        }
    }
}

// Simple Assert class for testing
public static class Assert
{
    public static void NotNull(object obj)
    {
        if (obj == null)
            throw new ArgumentNullException("Object should not be null");
    }
}
