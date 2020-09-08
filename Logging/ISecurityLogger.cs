using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Logging
{
    public interface ISecurityLogger
    {
        void LogEvent(LogLevel debugLevel, SecurityEventType securityEvent, string message);
        void LogEvent(LogLevel debugLevel, SecurityEventType securityEvent, string message, Exception ex);
    }
}
