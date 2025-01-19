using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace MiddlewareExample.Middlewares
{
    public class AuthorizationMiddleware
    {
        private readonly RequestDelegate _next;

        public AuthorizationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var endpoint = context.GetEndpoint();
            var authorizeAttribute = endpoint?.Metadata.GetMetadata<AuthorizeAttribute>();

            if(authorizeAttribute == null)
            {
                await _next(context);
                return;
            }

            var authorizationHeader = context.Request.Headers["Authorization"].ToString();

            if (string.IsNullOrEmpty(authorizationHeader))
            {
                await _next(context);
                return;
            }

            var token = authorizationHeader.Substring("Bearer ".Length).Trim();

            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadToken(token) as JwtSecurityToken;

            var roleClaim = jsonToken?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
            var scopeClaims = jsonToken?.Claims.Where(c => c.Type == "scope").Select(c => c.Value).ToList();

            var permissionAttribute = endpoint?.Metadata.GetMetadata<RequiredPermissionAttribute>();

            await _next(context);
        }
    }

    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class RequiredPermissionAttribute : Attribute
    {
        public string Permission { get; }

        public RequiredPermissionAttribute(string permission)
        {
            Permission = permission;
        }
    }
}
