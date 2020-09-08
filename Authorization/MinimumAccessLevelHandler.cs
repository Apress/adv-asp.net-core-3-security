using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Authorization
{
    public class MinimumAccessLevelHandler : AuthorizationHandler<MinimumAccessLevelRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MinimumAccessLevelRequirement requirement)
        {
            var userRoles = context.User.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);

            foreach (var role in userRoles)
            {
                if (requirement.RoleIsMatch(role))
                {
                    context.Succeed(requirement);
                    break;
                }
            }

            return Task.CompletedTask;
        }
    }
}
