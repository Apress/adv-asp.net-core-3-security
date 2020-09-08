using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Data.Primary
{
    public partial class CsrfToken
    {
        public Guid CsrfTokenId { get; set; }
        public DateTime ExpiresOn { get; set; }
        public string TokenValidOnPage { get; set; }
        public bool IsUsed { get; set; }
    }
}
