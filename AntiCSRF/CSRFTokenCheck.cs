using Advanced.Security.V3.Data.Primary;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.AntiCSRF
{
    public class CSRFTokenCheck : IAntiforgeryAdditionalDataProvider
    {
        private ApplicationDbContext _context;

        public CSRFTokenCheck(ApplicationDbContext context)
        {
            _context = context;
        }

        public string GetAdditionalData(HttpContext context)
        {
            var newID = Guid.NewGuid();

            var token = new CsrfToken();
            token.CsrfTokenId = newID;
            token.ExpiresOn = DateTime.Now.AddMinutes(5);
            token.TokenValidOnPage = context.Request.Path;
            token.IsUsed = false;

            _context.CsrfToken.Add(token);
            _context.SaveChanges();

            return newID.ToString();
        }

        public bool ValidateAdditionalData(HttpContext context, string additionalData)
        {
            if (string.IsNullOrEmpty(additionalData))
                return false;

            Guid toCheck;

            if (!Guid.TryParse(additionalData, out toCheck))
                return false;

            var dbToken = _context.CsrfToken.SingleOrDefault(t => t.CsrfTokenId == toCheck);

            if (dbToken == null)
                return false;

            if (dbToken.TokenValidOnPage != context.Request.Path)
                return false;

            var isUsed = dbToken.IsUsed;

            dbToken.IsUsed = true;
            _context.SaveChanges();

            return !isUsed;
        }
    }
}
