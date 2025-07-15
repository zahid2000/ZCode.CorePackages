﻿using System.Net.Mime;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using ZCode.Core.CrossCuttingConcerns.Exception.WebApi.Handlers;
//using ZCode.Core.CrossCuttingConcerns.Logging;
//using ZCode.Core.CrossCuttingConcerns.Logging.Abstraction;

namespace ZCode.Core.CrossCuttingConcerns.Exception.WebApi.Middleware;

public class ExceptionMiddleware
{
    private readonly IHttpContextAccessor _contextAccessor;
    private readonly HttpExceptionHandler _httpExceptionHandler;
    //private readonly ILogger _loggerService;
    private readonly RequestDelegate _next;

    public ExceptionMiddleware(RequestDelegate next, IHttpContextAccessor contextAccessor/*, ILogger loggerService*/)
    {
        _next = next;
        _contextAccessor = contextAccessor;
        //_loggerService = loggerService;
        _httpExceptionHandler = new HttpExceptionHandler();
    }

    public async Task Invoke(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (System.Exception exception)
        {
            //await LogException(context, exception);
            await HandleExceptionAsync(context.Response, exception);
        }
    }

    protected virtual Task HandleExceptionAsync(HttpResponse response, dynamic exception)
    {
        response.ContentType = MediaTypeNames.Application.Json;
        _httpExceptionHandler.Response = response;

        return _httpExceptionHandler.HandleException(exception);
    }

    //protected virtual Task LogException(HttpContext context, System.Exception exception)
    //{
    //    List<LogParameter> logParameters = [new LogParameter { Type = context.GetType().Name, Value = exception.ToString() }];

    //    LogDetail logDetail =
    //        new()
    //        {
    //            MethodName = _next.Method.Name,
    //            Parameters = logParameters,
    //            User = _contextAccessor.HttpContext?.User.Identity?.Name ?? "?"
    //        };

    //    _loggerService.Information(JsonSerializer.Serialize(logDetail));
    //    return Task.CompletedTask;
    //}
}
