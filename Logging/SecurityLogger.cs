using Advanced.Security.V3.Data.Primary;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Logging
{
    public class SecurityLogger : ISecurityLogger
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger _debugLogger;
        private readonly HttpContext _httpContext;
        private readonly UserManager<IdentityUser> _userManager;

        public SecurityLogger(ApplicationDbContext dbContext, IHttpContextAccessor httpAccessor, UserManager<IdentityUser> userManager)
            : this(dbContext, null, httpAccessor, userManager)
        {
        }

        public SecurityLogger(ApplicationDbContext dbContext, ILogger debugLogger, IHttpContextAccessor httpAccessor, UserManager<IdentityUser> userManager)
        {
            _dbContext = dbContext;
            _debugLogger = debugLogger;
            _httpContext = httpAccessor.HttpContext;
            _userManager = userManager;
        }

        public void LogEvent(LogLevel debugLevel, SecurityEventType securityEvent, string message)
        {
            var newEvent = new SecurityEventLog();

            newEvent.SecurityLevel = (int)securityEvent.EventLevel;
            newEvent.EventId = securityEvent.EventId;

            if (_httpContext.User != null)
            {
                newEvent.LoggedInUserId = _httpContext.User.Claims.SingleOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
            }

            newEvent.RequestIpaddress = _httpContext.Connection.RemoteIpAddress.ToString();
            newEvent.RequestPort = _httpContext.Connection.RemotePort;
            newEvent.RequestPath = _httpContext.Request.Path;
            newEvent.RequestQuery = _httpContext.Request.QueryString.ToString();

            string userAgent = !_httpContext.Request.Headers.ContainsKey("User-Agent") ? "" : _httpContext.Request.Headers["User-Agent"].ToString();

            if (userAgent.Length > 1000)
                userAgent = userAgent.Substring(0, 1000);

            newEvent.UserAgent = userAgent;
            newEvent.CreatedDateTime = DateTime.UtcNow;
            newEvent.AdditionalInfo = message;

            _dbContext.SecurityEventLog.Add(newEvent);
            _dbContext.SaveChanges();
        }

        public void LogEvent(LogLevel debugLevel, SecurityEventType securityEvent, string message, Exception ex)
        {
            var newEvent = new SecurityEventLog();

            newEvent.SecurityLevel = (int)securityEvent.EventLevel;
            newEvent.EventId = securityEvent.EventId;

            if (_httpContext.User != null)
            {
                newEvent.LoggedInUserId = _httpContext.User.Claims.SingleOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
            }

            newEvent.RequestIpaddress = _httpContext.Connection.RemoteIpAddress.ToString();
            newEvent.RequestPort = _httpContext.Connection.RemotePort;
            newEvent.RequestPath = _httpContext.Request.Path;
            newEvent.RequestQuery = _httpContext.Request.QueryString.ToString();

            string userAgent = !_httpContext.Request.Headers.ContainsKey("User-Agent") ? "" : _httpContext.Request.Headers["User-Agent"].ToString();

            if (userAgent.Length > 1000)
                userAgent = userAgent.Substring(0, 1000);

            newEvent.UserAgent = userAgent;
            newEvent.CreatedDateTime = DateTime.UtcNow;
            newEvent.AdditionalInfo = message;
            newEvent.StackTrace = ex.ToString();

            _dbContext.SecurityEventLog.Add(newEvent);
            _dbContext.SaveChanges();
        }
    }
}
