using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Data.Primary
{
    public partial class UserSession
    {
        public Guid UserSessionId { get; set; }
        public string UserId { get; set; }
        public DateTime ExpiresOn { get; set; }
    }
}
