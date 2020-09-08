using Advanced.Security.V3.Cryptography;
using Advanced.Security.V3.Cryptography.Hashing;
using Advanced.Security.V3.Logging;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Authentication
{
    public class CustomSignInManager : SignInManager<IdentityUser>
    {
        ISecurityLogger _securityLogger;
        IHasher _hasher;

        public CustomSignInManager(UserManager<IdentityUser> userManager,
            IHttpContextAccessor contextAccessor,
            IUserClaimsPrincipalFactory<IdentityUser> claimsFactory,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<IdentityUser>> logger,
            IAuthenticationSchemeProvider schemes,
            IUserConfirmation<IdentityUser> confirmation,
            ISecurityLogger securityLogger,
            IHasher hasher) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
        {
            _securityLogger = securityLogger;
            _hasher = hasher;
        }

        public override async Task<SignInResult> PasswordSignInAsync(string userName, string password,
            bool isPersistent, bool lockoutOnFailure)
        {
            var user = await UserManager.FindByNameAsync(userName);

            if (user == null)
            {
                var hashedUserName = _hasher.CreateHash(userName, BaseCryptographyItem.HashAlgorithm.SHA2_512);
                _securityLogger.LogEvent(LogLevel.Debug, SecurityEvent.Authentication.USER_NOT_FOUND, $"Login failed because username not found: {hashedUserName}");
            }


            //We need to run all code regardless of whether the user exists, so remove this check
            //if (user == null)
            //{
            //    return SignInResult.Failed;
            //}

            return await PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
        }

        public override async Task<SignInResult> PasswordSignInAsync(IdentityUser user, string password,
            bool isPersistent, bool lockoutOnFailure)
        {
            //Remove the null check
            //if (user == null)
            //{
            //    throw new ArgumentNullException(nameof(user));
            //}

            var attempt = await CheckPasswordSignInAsync(user, password, lockoutOnFailure);
            return attempt.Succeeded
                ? await SignInOrTwoFactorAsync(user, isPersistent)
                : attempt;
        }

        public override async Task<SignInResult> CheckPasswordSignInAsync(IdentityUser user, string password, bool lockoutOnFailure)
        {
            //Skip the user null check
            //if (user == null)
            //{
            //    throw new ArgumentNullException(nameof(user));
            //}

            var error = await PreSignInCheck(user);
            if (error != null)
            {
                return error;
            }

            if (await UserManager.CheckPasswordAsync(user, password))
            {
                var alwaysLockout = AppContext.TryGetSwitch("Microsoft.AspNetCore.Identity.CheckPasswordSignInAlwaysResetLockoutOnSuccess", out var enabled) && enabled;
                // Only reset the lockout when TFA is not enabled when not in quirks mode
                if (alwaysLockout || !await IsTfaEnabled(user))
                {
                    await ResetLockout(user);
                }

                return SignInResult.Success;
            }
            else if (user != null)
            {
                _securityLogger.LogEvent(LogLevel.Debug, SecurityEvent.Authentication.PASSWORD_MISMATCH, "Login failed because password didn't match");
            }

            var userId = user != null ? UserManager.GetUserIdAsync(user).Result : "(null)";
            Logger.LogWarning(2, "User {userId} failed to provide the correct password.", userId);

            if (UserManager.SupportsUserLockout && lockoutOnFailure && user != null)
            {
                // If lockout is requested, increment access failed count which might lock out the user
                await UserManager.AccessFailedAsync(user);
                if (await UserManager.IsLockedOutAsync(user))
                {
                    return await LockedOut(user);
                }
            }
            return SignInResult.Failed;
        }

        protected override async Task<SignInResult> PreSignInCheck(IdentityUser user)
        {
            //Skip processing if the user is null
            if (user == null)
                return null;

            if (!await CanSignInAsync(user))
            {
                return SignInResult.NotAllowed;
            }
            if (await IsLockedOut(user))
            {
                return await LockedOut(user);
            }
            return null;
        }

        private async Task<bool> IsTfaEnabled(IdentityUser user)
            => UserManager.SupportsUserTwoFactor &&
            await UserManager.GetTwoFactorEnabledAsync(user) &&
            (await UserManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;
    }
}
