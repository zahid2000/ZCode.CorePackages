using Mapster;
using ZCode.Core.Application.Mapping.Services;

namespace ZCode.Core.Application.Mapping.Mapster.Services;

public class MapsterService : IMapperService
{
    private readonly TypeAdapterConfig _config;

    public MapsterService(TypeAdapterConfig config)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
    }

    public TDestination Map<TDestination>(object source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        return source.Adapt<TDestination>(_config);
    }

    public TDestination Map<TSource, TDestination>(TSource source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        return source.Adapt<TSource, TDestination>(_config);
    }

    public TDestination Map<TSource, TDestination>(TSource source, TDestination destination)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));
        
        if (destination == null)
            throw new ArgumentNullException(nameof(destination));

        return source.Adapt(destination, _config);
    }

    public IEnumerable<TDestination> Map<TDestination>(IEnumerable<object> source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        return source.Adapt<IEnumerable<TDestination>>(_config);
    }

    public IEnumerable<TDestination> Map<TSource, TDestination>(IEnumerable<TSource> source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        return source.Adapt<IEnumerable<TSource>, IEnumerable<TDestination>>(_config);
    }
}
