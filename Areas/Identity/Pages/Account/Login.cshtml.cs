using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Advanced.Security.V3.Data.Primary;
using Advanced.Security.V3.Logging;
using Advanced.Security.V3.Authentication;

namespace Advanced.Security.V3.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        private readonly CustomUserManager _userManager;
        private readonly CustomSignInManager _signInManager;
        private readonly ISecurityLogger _logger;
        private readonly ApplicationDbContext _dbContext;

        public LoginModel(SignInManager<IdentityUser> signInManager,
            ISecurityLogger logger,
            UserManager<IdentityUser> userManager,
            ApplicationDbContext dbContext)
        {
            _userManager = (CustomUserManager)userManager;
            _signInManager = (CustomSignInManager)signInManager;
            _logger = logger;
            _dbContext = dbContext;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl = returnUrl ?? Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            if (!CanAccessPage())
                return RedirectToPage("./Lockout");

            returnUrl = returnUrl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    _logger.LogEvent(LogLevel.Information, SecurityEvent.Authentication.LOGIN_SUCCESSFUL, "User logged in");
                    return LocalRedirect(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    _logger.LogEvent(LogLevel.Information, SecurityEvent.Authentication.LOGIN_SUCCESS_2FA_REQUIRED, "2FA required");
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogEvent(LogLevel.Warning, SecurityEvent.Authentication.USER_LOCKED_OUT, "User account locked out");
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }

        private bool CanAccessPage()
        {
            var sourceIp = HttpContext.Connection.RemoteIpAddress.ToString();

            var failedUsername = _dbContext.SecurityEventLog.Where(l => l.CreatedDateTime > DateTime.UtcNow.AddDays(-1) &&
                                                                        l.RequestIpaddress == sourceIp &&
                                                                        l.EventId == SecurityEvent.Authentication.USER_NOT_FOUND.EventId)
                                                            .Select(l => l.AdditionalInfo)
                                                            .Distinct()
                                                            .Count();

            var failedPassword = _dbContext.SecurityEventLog.Count(l => l.CreatedDateTime > DateTime.UtcNow.AddDays(-1) &&
                                                                        l.RequestIpaddress == sourceIp &&
                                                                        l.EventId == SecurityEvent.Authentication.PASSWORD_MISMATCH.EventId);

            if (failedUsername >= 5 || failedPassword >= 20)
                return false;
            else
                return true;
        }
    }
}
