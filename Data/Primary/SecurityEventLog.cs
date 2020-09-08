using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Data.Primary
{
    public partial class SecurityEventLog
    {
        public long SecurityEventLogId { get; set; }
        public int SecurityLevel { get; set; }
        public int EventId { get; set; }
        public string LoggedInUserId { get; set; }
        public string RequestIpaddress { get; set; }
        public int? RequestPort { get; set; }
        public DateTime CreatedDateTime { get; set; }
        public string AdditionalInfo { get; set; }
        public string UserAgent { get; set; }
        public string RequestPath { get; set; }
        public string RequestQuery { get; set; }
        public string StackTrace { get; set; }
    }
}
