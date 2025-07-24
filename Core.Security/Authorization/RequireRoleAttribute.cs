using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using ZCode.Core.Security.Abstraction;

namespace ZCode.Core.Security.Authorization;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RequireRoleAttribute : Attribute, IAuthorizationFilter
{
    private readonly string[] _roles;

    public RequireRoleAttribute(params string[] roles)
    {
        _roles = roles ?? throw new ArgumentNullException(nameof(roles));
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

        bool hasRequiredRole = _roles.Any(role => currentUserService.IsInRole(role));
        if (!hasRequiredRole)
        {
            context.Result = new ForbidResult();
            return;
        }
    }
}
