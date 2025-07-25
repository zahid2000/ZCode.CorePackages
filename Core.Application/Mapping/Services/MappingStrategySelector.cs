using Microsoft.Extensions.DependencyInjection;

namespace ZCode.Core.Application.Mapping.Services;

public enum MappingStrategy
{
    AutoMapper,
    Mapster
}

public interface IMappingStrategySelector
{
    IMapperService GetMapper(MappingStrategy strategy);
}

public class MappingStrategySelector : IMappingStrategySelector
{
    private readonly IServiceProvider _serviceProvider;

    public MappingStrategySelector(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public IMapperService GetMapper(MappingStrategy strategy)
    {
        return strategy switch
        {
            MappingStrategy.AutoMapper => _serviceProvider.GetKeyedService<IMapperService>("AutoMapper") 
                ?? throw new InvalidOperationException("AutoMapper service not registered"),
            MappingStrategy.Mapster => _serviceProvider.GetKeyedService<IMapperService>("Mapster") 
                ?? throw new InvalidOperationException("Mapster service not registered"),
            _ => throw new ArgumentOutOfRangeException(nameof(strategy), strategy, null)
        };
    }
}
