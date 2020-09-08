using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Authentication
{
    public class CustomUserManager : UserManager<IdentityUser>
    {
        public CustomUserManager(IUserStore<IdentityUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<IdentityUser> passwordHasher,
            IEnumerable<IUserValidator<IdentityUser>> userValidators,
            IEnumerable<IPasswordValidator<IdentityUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<IdentityUser>> logger) : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
        }

        public override async Task<bool> CheckPasswordAsync(IdentityUser user, string password)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();

            var result = await VerifyPasswordAsync(passwordStore, user, password);
            if (result == PasswordVerificationResult.SuccessRehashNeeded)
            {
                //Remove the IPasswordStore parameter so we can call the protected, not private, method
                await UpdatePasswordHash(user, password, validatePassword: false);
                await UpdateUserAsync(user);
            }

            var success = result != PasswordVerificationResult.Failed;
            if (!success)
            {
                var userId = user != null ? GetUserIdAsync(user).Result : "(null)";
                Logger.LogWarning(0, "Invalid password for user {userId}.", userId);
            }
            return success;
        }

        protected override async Task<PasswordVerificationResult> VerifyPasswordAsync(IUserPasswordStore<IdentityUser> store, IdentityUser user, string password)
        {
            string existingHash;

            if (user != null)
                existingHash = await store.GetPasswordHashAsync(user, CancellationToken);
            else
                existingHash = "not a real hash";

            if (existingHash == null)
            {
                return PasswordVerificationResult.Failed;
            }
            return PasswordHasher.VerifyHashedPassword(user, existingHash, password);
        }

        public override async Task<IdentityUser> FindByNameAsync(string userName)
        {
            if (userName == null)
            {
                throw new ArgumentNullException(nameof(userName));
            }

            IdentityUser user;

            if (Store is CustomUserStore)
            {
                user = await ((CustomUserStore)Store).FindByNameCaseSensitiveAsync(userName, CancellationToken);
            }
            else
            {
                userName = NormalizeName(userName);
                user = await Store.FindByNameAsync(userName, CancellationToken);
            }

            // Need to potentially check all keys
            if (user == null && Options.Stores.ProtectPersonalData)
            {
                //Use wrapper method, not reference to private field
                var keyRing = GetServices().GetService<ILookupProtectorKeyRing>();
                var protector = GetServices().GetService<ILookupProtector>();
                if (keyRing != null && protector != null)
                {
                    foreach (var key in keyRing.GetAllKeyIds())
                    {
                        var oldKey = protector.Protect(key, userName);
                        user = await Store.FindByNameAsync(oldKey, CancellationToken);
                        if (user != null)
                        {
                            return user;
                        }
                    }
                }
            }
            return user;
        }

        public override async Task<IdentityResult> AddPasswordAsync(IdentityUser user, string password)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var hash = await passwordStore.GetPasswordHashAsync(user, CancellationToken);
            if (hash != null)
            {
                Logger.LogWarning(1, "User {userId} already has a password.", await GetUserIdAsync(user));
                return IdentityResult.Failed(ErrorDescriber.UserAlreadyHasPassword());
            }
            //Remove the IPasswordStore parameter so we can call the protected, not private, method
            var result = await UpdatePasswordHash(user, password, validatePassword: false);
            if (!result.Succeeded)
            {
                return result;
            }
            if (Store is CustomUserStore)
            {
                await ((CustomUserStore)Store).AddPasswordHistoryItem(user, password);
            }
            return await UpdateUserAsync(user);
        }

        public override async Task<IdentityResult> ChangePasswordAsync(IdentityUser user, string currentPassword, string newPassword)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (await VerifyPasswordAsync(passwordStore, user, currentPassword) != PasswordVerificationResult.Failed)
            {
                //Remove the IPasswordStore parameter so we can call the protected, not private, method
                var result = await UpdatePasswordHash(user, newPassword, validatePassword: false);
                if (!result.Succeeded)
                {
                    return result;
                }

                if (Store is CustomUserStore)
                {
                    await ((CustomUserStore)Store).AddPasswordHistoryItem(user, newPassword);
                }

                return await UpdateUserAsync(user);
            }
            Logger.LogWarning(2, "Change password failed for user {userId}.", await GetUserIdAsync(user));
            return IdentityResult.Failed(ErrorDescriber.PasswordMismatch());
        }

        public bool IsPasswordExpired(IdentityUser user)
        {
            if (Store is CustomUserStore)
            {
                var expires = ((CustomUserStore)Store).GetPasswordExpiration(user);

                //Leave this check in if adding password history to an existing system
                if (expires == null || !expires.HasValue)
                    return false;
                else
                    return expires.Value < DateTime.UtcNow;
            }
            else
            {
                return false;
            }
        }

        protected bool IsNewPasswordValid(IdentityUser user, string password)
        {
            if (Store is CustomUserStore)
            {
                var expires = ((CustomUserStore)Store).GetPasswordExpiration(user);

                //Leave this check in if adding password history to an existing system
                if (expires == null || !expires.HasValue)
                    return false;
                else
                    return expires.Value < DateTime.UtcNow;
            }
            else
            {
                return false;
            }
        }

        //Wrapper method to access private field in base class
        private IServiceProvider GetServices()
        {
            return (IServiceProvider)this.GetType().BaseType.GetField("_services", BindingFlags.Instance | BindingFlags.NonPublic);
        }

        private IUserPasswordStore<IdentityUser> GetPasswordStore()
        {
            var cast = Store as IUserPasswordStore<IdentityUser>;
            if (cast == null)
            {
                throw new NotSupportedException("IUserStore must implement IUserPasswordStore");
            }
            return cast;
        }
    }
}
