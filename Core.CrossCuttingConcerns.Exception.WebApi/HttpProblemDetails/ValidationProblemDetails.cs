﻿using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ZCode.Core.CrossCuttingConcerns.Exception.Types;

namespace ZCode.Core.CrossCuttingConcerns.Exception.WebApi.HttpProblemDetails;

public class ValidationProblemDetails : ProblemDetails
{
    public IEnumerable<ValidationExceptionModel> Errors { get; init; }

    public ValidationProblemDetails(IEnumerable<ValidationExceptionModel> errors)
    {
        Title = "Validation error(s)";
        Detail = "One or more validation errors occurred.";
        Errors = errors;
        Status = StatusCodes.Status400BadRequest;
        Type = "https://example.com/probs/validation";
    }
}
