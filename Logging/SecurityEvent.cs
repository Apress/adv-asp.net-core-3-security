using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Logging
{
    public class SecurityEvent
    {
        public class Authentication
        {
            public static SecurityEventType LOGIN_SUCCESSFUL { get; } = new SecurityEventType(1200, SecurityEventType.SecurityLevel.SECURITY_SUCCESS);
            public static SecurityEventType LOGOUT_SUCCESSFUL { get; } = new SecurityEventType(1201, SecurityEventType.SecurityLevel.SECURITY_SUCCESS);
            public static SecurityEventType PASSWORD_MISMATCH { get; } = new SecurityEventType(1202, SecurityEventType.SecurityLevel.SECURITY_INFO);
            public static SecurityEventType USER_LOCKED_OUT { get; } = new SecurityEventType(1203, SecurityEventType.SecurityLevel.SECURITY_WARNING);
            public static SecurityEventType USER_NOT_FOUND { get; } = new SecurityEventType(1204, SecurityEventType.SecurityLevel.SECURITY_WARNING);
            public static SecurityEventType LOGIN_SUCCESS_2FA_REQUIRED { get; } = new SecurityEventType(1210, SecurityEventType.SecurityLevel.SECURITY_INFO);
        }

        public class General
        {
            public static SecurityEventType EXCEPTION { get; } = new SecurityEventType(1, SecurityEventType.SecurityLevel.SECURITY_ERROR);
        }

        public class Honeypot
        {
            public static SecurityEventType REQUEST_OPTIONS { get; } = new SecurityEventType(2401, SecurityEventType.SecurityLevel.SECURITY_INFO);
            public static SecurityEventType REQUEST_GET { get; } = new SecurityEventType(2402, SecurityEventType.SecurityLevel.SECURITY_INFO);
            public static SecurityEventType REQUEST_HEAD { get; } = new SecurityEventType(2403, SecurityEventType.SecurityLevel.SECURITY_INFO);
            public static SecurityEventType REQUEST_POST { get; } = new SecurityEventType(2404, SecurityEventType.SecurityLevel.SECURITY_WARNING);
            public static SecurityEventType REQUEST_PUT { get; } = new SecurityEventType(2405, SecurityEventType.SecurityLevel.SECURITY_WARNING);
            public static SecurityEventType REQUEST_DELETE { get; } = new SecurityEventType(2406, SecurityEventType.SecurityLevel.SECURITY_WARNING);
            public static SecurityEventType REQUEST_TRACE { get; } = new SecurityEventType(2407, SecurityEventType.SecurityLevel.SECURITY_INFO);
            public static SecurityEventType REQUEST_CONNECT { get; } = new SecurityEventType(2408, SecurityEventType.SecurityLevel.SECURITY_INFO);
            public static SecurityEventType REQUEST_UNKNOWN { get; } = new SecurityEventType(2409, SecurityEventType.SecurityLevel.SECURITY_INFO);
        }

        public class HTTP
        {
            public static SecurityEventType PAGE_NOT_FOUND { get; } = new SecurityEventType(404, SecurityEventType.SecurityLevel.SECURITY_WARNING);
        }
    }
}
