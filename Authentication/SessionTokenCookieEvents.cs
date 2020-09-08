using Advanced.Security.V3.Data.Primary;
using Microsoft.AspNetCore.Authentication.Cookies;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Authentication
{
    public class SessionTokenCookieEvents : CookieAuthenticationEvents
    {
        private const string _claimsKey = "UniqueSessionId";

        public override Task SigningIn(CookieSigningInContext context)
        {
            var userIdClaim = context.Principal.Claims.SingleOrDefault(c => c.Type == ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
                throw new NullReferenceException("User ID Claim cannot be null");

            var dbContext = (ApplicationDbContext)context.HttpContext.RequestServices.GetService(typeof(ApplicationDbContext));

            var newSessionId = Guid.NewGuid();

            var newSessionObj = new UserSession();

            newSessionObj.UserSessionId = newSessionId;
            newSessionObj.UserId = userIdClaim.Value;
            newSessionObj.ExpiresOn = DateTime.Now.AddMinutes(10);

            dbContext.UserSession.Add(newSessionObj);
            dbContext.SaveChanges();

            var claims = new List<Claim>();
            claims.Add(new Claim(_claimsKey, newSessionId.ToString()));
            var appIdentity = new ClaimsIdentity(claims);
            context.Principal.AddIdentity(appIdentity);

            return base.SigningIn(context);
        }

        public override Task SigningOut(CookieSigningOutContext context)
        {
            if (context == null)
                throw new ArgumentNullException("context cannot be null");

            var userIdClaim = context.HttpContext.User.Claims.SingleOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            var sessionClaim = context.HttpContext.User.Claims.SingleOrDefault(c => c.Type == _claimsKey);

            Guid sessionId;

            if (!Guid.TryParse(sessionClaim.Value, out sessionId))
            {
                //Log this?
            }

            var dbContext = (ApplicationDbContext)context.HttpContext.RequestServices.GetService(typeof(ApplicationDbContext));

            var sessionObject = dbContext.UserSession.SingleOrDefault(s => s.UserId == userIdClaim.Value && s.UserSessionId == sessionId);

            if (sessionObject != null)
            {
                dbContext.UserSession.Remove(sessionObject);
                dbContext.SaveChanges();
            }

            return base.SigningOut(context);
        }

        public override Task ValidatePrincipal(CookieValidatePrincipalContext context)
        {
            if (context == null)
                throw new ArgumentNullException("context cannot be null");

            var userIdClaim = context.Principal.Claims.SingleOrDefault(c => c.Type == ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
            {
                context.RejectPrincipal();
                return Task.CompletedTask;
            }

            var sessionClaim = context.Principal.Claims.SingleOrDefault(c => c.Type == _claimsKey);

            if (sessionClaim == null)
            {
                context.RejectPrincipal();
                return Task.CompletedTask;
            }

            Guid sessionId;

            if (!Guid.TryParse(sessionClaim.Value, out sessionId))
            {
                context.RejectPrincipal();
                return Task.CompletedTask;
            }

            var dbContext = (ApplicationDbContext)context.HttpContext.RequestServices.GetService(typeof(ApplicationDbContext));

            var sessionObject = dbContext.UserSession.SingleOrDefault(s => s.UserId == userIdClaim.Value && s.UserSessionId == sessionId);

            if (sessionObject == null || sessionObject.ExpiresOn < DateTime.Now)
            {
                context.RejectPrincipal();
                return Task.CompletedTask;
            }

            return base.ValidatePrincipal(context);
        }
    }
}
