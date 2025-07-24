using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using ZCode.Core.Security.Abstraction;

namespace ZCode.Core.Security.Authorization;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RequirePermissionAttribute : Attribute, IAuthorizationFilter
{
    private readonly string[] _permissions;

    public RequirePermissionAttribute(params string[] permissions)
    {
        _permissions = permissions ?? throw new ArgumentNullException(nameof(permissions));
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var currentUserService = context.HttpContext.RequestServices
            .GetService<ICurrentUserService>();

        if (currentUserService == null)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        if (!currentUserService.IsAuthenticated)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        bool hasRequiredPermission = _permissions.Any(permission => 
            currentUserService.HasPermission(permission));
        
        if (!hasRequiredPermission)
        {
            context.Result = new ForbidResult();
            return;
        }
    }
}
