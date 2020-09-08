using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.AntiCSRF
{
    public class CSRFExpirationCheck : IAntiforgeryAdditionalDataProvider
    {
        private const int EXPIRATION_MINUTES = 10;

        public string GetAdditionalData(HttpContext context)
        {
            return DateTime.Now.AddMinutes(EXPIRATION_MINUTES).ToString();
        }

        public bool ValidateAdditionalData(HttpContext context, string additionalData)
        {
            if (string.IsNullOrEmpty(additionalData))
                return false;

            DateTime toCheck;

            if (!DateTime.TryParse(additionalData, out toCheck))
                return false;

            return toCheck >= DateTime.Now;
        }
    }
}
