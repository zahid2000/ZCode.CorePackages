using AutoMapper;
using ZCode.Core.Application.Mapping.Services;

namespace ZCode.Core.Application.Mapping.AutoMapper.Services;

public class AutoMapperService : IMapperService
{
    private readonly IMapper _mapper;

    public AutoMapperService(IMapper mapper)
    {
        _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
    }

    public TDestination Map<TDestination>(object source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        return _mapper.Map<TDestination>(source);
    }

    public TDestination Map<TSource, TDestination>(TSource source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        return _mapper.Map<TSource, TDestination>(source);
    }

    public TDestination Map<TSource, TDestination>(TSource source, TDestination destination)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));
        
        if (destination == null)
            throw new ArgumentNullException(nameof(destination));

        return _mapper.Map(source, destination);
    }

    public IEnumerable<TDestination> Map<TDestination>(IEnumerable<object> source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        return _mapper.Map<IEnumerable<TDestination>>(source);
    }

    public IEnumerable<TDestination> Map<TSource, TDestination>(IEnumerable<TSource> source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        return _mapper.Map<IEnumerable<TSource>, IEnumerable<TDestination>>(source);
    }
}
