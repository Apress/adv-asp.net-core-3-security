using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Advanced.Security.V3.Pages
{
    public class CSPNonceTestModel : PageModel
    {
        private readonly string _nonce;

        public CSPNonceTestModel()
        {
            _nonce = Guid.NewGuid().ToString().Replace("-", "");
        }

        public void OnGet()
        {
            if (Response.Headers.ContainsKey("Content-Security-Policy"))
                Response.Headers.Remove("Content-Security-Policy");

            Response.Headers.Add("Content-Security-Policy", $"Content-Security-Policy: default-src 'self'; script-src 'nonce-{_nonce}'; style-src 'self'");

            ViewData["Nonce"] = _nonce;
        }
    }
}