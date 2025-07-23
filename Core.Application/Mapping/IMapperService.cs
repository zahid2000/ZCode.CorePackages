namespace ZCode.Core.Application.Mapping;

public interface IMapperService
{
    TDestination Map<TDestination>(object source);
    TDestination Map<TSource, TDestination>(TSource source);
    TDestination Map<TSource, TDestination>(TSource source, TDestination destination);
    IEnumerable<TDestination> Map<TDestination>(IEnumerable<object> source);
    IEnumerable<TDestination> Map<TSource, TDestination>(IEnumerable<TSource> source);
}
