using Advanced.Security.V3.Logging;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.ResourceFilters
{
    public class HoneypotAttribute : Attribute, IResourceFilter
    {
		public void OnResourceExecuted(ResourceExecutedContext context)
		{
			//do nothing
		}

		public void OnResourceExecuting(ResourceExecutingContext context)
		{
			var _logger = (ISecurityLogger)context.HttpContext.RequestServices.GetService(typeof(ISecurityLogger));
			var message = $"Path: {context.HttpContext.Request.Path}";

			switch (context.HttpContext.Request.Method.ToLower())
			{
				case "options":
					_logger.LogEvent(LogLevel.Information, SecurityEvent.Honeypot.REQUEST_OPTIONS, message);
					break;
				case "get":
					_logger.LogEvent(LogLevel.Information, SecurityEvent.Honeypot.REQUEST_GET, message);
					break;
				case "head":
					_logger.LogEvent(LogLevel.Information, SecurityEvent.Honeypot.REQUEST_HEAD, message);
					break;
				case "post":
					_logger.LogEvent(LogLevel.Information, SecurityEvent.Honeypot.REQUEST_POST, message);
					break;
				case "put":
					_logger.LogEvent(LogLevel.Information, SecurityEvent.Honeypot.REQUEST_PUT, message);
					break;
				case "delete":
					_logger.LogEvent(LogLevel.Information, SecurityEvent.Honeypot.REQUEST_DELETE, message);
					break;
				case "trace":
					_logger.LogEvent(LogLevel.Information, SecurityEvent.Honeypot.REQUEST_TRACE, message);
					break;
				case "connect":
					_logger.LogEvent(LogLevel.Information, SecurityEvent.Honeypot.REQUEST_CONNECT, message);
					break;
				default:
					_logger.LogEvent(LogLevel.Information, SecurityEvent.Honeypot.REQUEST_UNKNOWN, $"Unknown security event type {context.HttpContext.Request.Method} at {message}");
					break;
			}
		}
	}
}
