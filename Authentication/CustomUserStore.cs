using Advanced.Security.V3.Cryptography;
using Advanced.Security.V3.Cryptography.Hashing;
using Advanced.Security.V3.Data.Primary;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Authentication
{
    //IUserPasswordStore is necessary because the framework expects the IUserStore to also implement the IUserPasswordStore
    public class CustomUserStore : IUserStore<IdentityUser>, IUserPasswordStore<IdentityUser>, IUserEmailStore<IdentityUser>, IUserPhoneNumberStore<IdentityUser>,
        IUserRoleStore<IdentityUser>, IUserLockoutStore<IdentityUser>, IUserClaimStore<IdentityUser>, IUserLoginStore<IdentityUser>
    {
        private readonly IHasher _hasher;

        //Consider not using your main DB context here and using ADO.NET instead
        //EF will save any changes you've made to the object when SaveChanges() is called
        //Including unencrypted versions of PII that you *don't* want stored in the database
        private readonly ApplicationDbContext _dbContext;
        private readonly ICryptoStoreSimulator _cryptoStore;
        private readonly IPasswordHasher<IdentityUser> _passwordHasher;

        public CustomUserStore(IHasher hasher, ApplicationDbContext dbContext, ICryptoStoreSimulator cryptoStore, IPasswordHasher<IdentityUser> passwordHasher)
        {
            _hasher = hasher;
            _dbContext = dbContext;
            _cryptoStore = cryptoStore;
            _passwordHasher = passwordHasher;
        }

        #region IUserStore
        public Task<IdentityResult> CreateAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            var userName = user.UserName;
            var email = user.Email;
            var normalizedUserName = user.NormalizedUserName;
            var normalizedEmail = user.NormalizedEmail;
            var phone = user.PhoneNumber;

            //Set values to hashed values for saving
            //If you use ADO.NET directly, you won't have to use this work-around
            user.UserName = _hasher.CreateHash(user.UserName, CryptoStoreSimulator.KEYNAME_USERNAME, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            user.Email = _hasher.CreateHash(user.Email, CryptoStoreSimulator.KEYNAME_EMAIL, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            user.NormalizedUserName = _hasher.CreateHash(user.NormalizedUserName, CryptoStoreSimulator.KEYNAME_NORMALIZED_USERNAME, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            user.NormalizedEmail = _hasher.CreateHash(user.NormalizedEmail, CryptoStoreSimulator.KEYNAME_NORMALIZED_EMAIL, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            user.PhoneNumber = _hasher.CreateHash(user.PhoneNumber, CryptoStoreSimulator.KEYNAME_PHONE, BaseCryptographyItem.HashAlgorithm.SHA2_512);

            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            _cryptoStore.SaveUserEmail(user.Id, email);
            _cryptoStore.SaveUserName(user.Id, userName);
            _cryptoStore.SaveNormalizedUserEmail(user.Id, normalizedEmail);
            _cryptoStore.SaveNormalizedUserName(user.Id, normalizedUserName);
            _cryptoStore.SavePhoneNumber(user.Id, phone);

            //Set these back to the original for processing in the website
            user.UserName = userName;
            user.Email = email;
            user.NormalizedUserName = normalizedUserName;
            user.NormalizedEmail = normalizedEmail;
            user.PhoneNumber = phone;

            _dbContext.Entry(user).State = EntityState.Detached;

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> DeleteAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            //Don't forget to delete the keys!
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            //throw new NotImplementedException();
        }

        public Task<IdentityUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var user = _dbContext.Users.SingleOrDefault(u => u.Id == userId);

            if (user != null)
            {
                user.UserName = _cryptoStore.GetUserName(user.Id);
                user.Email = _cryptoStore.GetUserEmail(user.Id);
                user.NormalizedUserName = _cryptoStore.GetNormalizedUserName(user.Id);
                user.NormalizedEmail = _cryptoStore.GetNormalizedUserEmail(user.Id);
                user.PhoneNumber = _cryptoStore.GetPhoneNumber(user.Id);

                _dbContext.Entry(user).State = EntityState.Detached;
            }

            return Task.FromResult(user);
        }

        public Task<IdentityUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            var hashedUserName = _hasher.CreateHash(normalizedUserName, CryptoStoreSimulator.KEYNAME_NORMALIZED_USERNAME, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            var user = _dbContext.Users.SingleOrDefault(u => u.NormalizedUserName == hashedUserName);

            if (user != null)
            {
                user.UserName = _cryptoStore.GetUserName(user.Id);
                user.Email = _cryptoStore.GetUserEmail(user.Id);
                user.NormalizedUserName = _cryptoStore.GetNormalizedUserName(user.Id);
                user.NormalizedEmail = _cryptoStore.GetNormalizedUserEmail(user.Id);
                user.PhoneNumber = _cryptoStore.GetPhoneNumber(user.Id);

                _dbContext.Entry(user).State = EntityState.Detached;
            }

            return Task.FromResult(user);
        }

        public Task<string> GetNormalizedUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.NormalizedUserName);
        }

        public Task<string> GetUserIdAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserName);
        }

        public Task SetNormalizedUserNameAsync(IdentityUser user, string normalizedName, CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
            return Task.CompletedTask;
        }

        public Task SetUserNameAsync(IdentityUser user, string userName, CancellationToken cancellationToken)
        {
            user.UserName = userName;
            return Task.CompletedTask;
        }

        public Task<IdentityResult> UpdateAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            var userName = user.UserName;
            var email = user.Email;
            var normalizedUserName = user.NormalizedUserName;
            var normalizedEmail = user.NormalizedEmail;
            var phone = user.PhoneNumber;

            //Set values to hashed values for saving
            //If you use ADO.NET directly, you won't have to use this work-around
            user.UserName = _hasher.CreateHash(user.UserName, CryptoStoreSimulator.KEYNAME_USERNAME, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            user.Email = _hasher.CreateHash(user.Email, CryptoStoreSimulator.KEYNAME_EMAIL, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            user.NormalizedUserName = _hasher.CreateHash(user.NormalizedUserName, CryptoStoreSimulator.KEYNAME_NORMALIZED_USERNAME, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            user.NormalizedEmail = _hasher.CreateHash(user.NormalizedEmail, CryptoStoreSimulator.KEYNAME_NORMALIZED_EMAIL, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            user.PhoneNumber = _hasher.CreateHash(user.PhoneNumber, CryptoStoreSimulator.KEYNAME_PHONE, BaseCryptographyItem.HashAlgorithm.SHA2_512);

            _dbContext.Users.Attach(user);
            _dbContext.SaveChanges();

            _cryptoStore.SaveUserEmail(user.Id, email);
            _cryptoStore.SaveUserName(user.Id, userName);
            _cryptoStore.SaveNormalizedUserEmail(user.Id, normalizedEmail);
            _cryptoStore.SaveNormalizedUserName(user.Id, normalizedUserName);
            _cryptoStore.SavePhoneNumber(user.Id, phone);

            //Set these back to the original for processing in the website
            user.UserName = userName;
            user.Email = email;
            user.NormalizedUserName = normalizedUserName;
            user.NormalizedEmail = normalizedEmail;
            user.PhoneNumber = phone;

            _dbContext.Entry(user).State = EntityState.Detached;

            return Task.FromResult(IdentityResult.Success);
        }
        #endregion

        #region IUserPasswordStore
        public Task<string> GetPasswordHashAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash != null && user.PasswordHash.Length > 0);
        }

        public Task SetPasswordHashAsync(IdentityUser user, string passwordHash, CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;
            return Task.CompletedTask;
        }
        #endregion

        #region IUserEmailStore
        public Task<IdentityUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            var hashedEmail = _hasher.CreateHash(normalizedEmail, CryptoStoreSimulator.KEYNAME_NORMALIZED_EMAIL, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            var user = _dbContext.Users.SingleOrDefault(u => u.NormalizedEmail == hashedEmail);

            if (user != null)
            {
                user.UserName = _cryptoStore.GetUserName(user.Id);
                user.Email = _cryptoStore.GetUserEmail(user.Id);
                user.NormalizedUserName = _cryptoStore.GetNormalizedUserName(user.Id);
                user.NormalizedEmail = _cryptoStore.GetNormalizedUserEmail(user.Id);
                user.PhoneNumber = _cryptoStore.GetPhoneNumber(user.Id);

                _dbContext.Entry(user).State = EntityState.Detached;
            }

            return Task.FromResult(user);
        }

        public Task<string> GetEmailAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.EmailConfirmed);
        }

        public Task<string> GetNormalizedEmailAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.NormalizedEmail);
        }

        public Task SetEmailAsync(IdentityUser user, string email, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailConfirmedAsync(IdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.EmailConfirmed = confirmed;
            return Task.CompletedTask;
        }

        public Task SetNormalizedEmailAsync(IdentityUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            user.NormalizedEmail = normalizedEmail;
            return Task.CompletedTask;
        }

        #endregion

        #region IUserPhoneNumberStore
        public Task<string> GetPhoneNumberAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberAsync(IdentityUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            user.PhoneNumber = phoneNumber;
            return Task.CompletedTask;
        }

        public Task SetPhoneNumberConfirmedAsync(IdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.PhoneNumberConfirmed = confirmed;
            return Task.CompletedTask;
        }
        #endregion

        #region Custom Methods
        public Task<IdentityUser> FindByNameCaseSensitiveAsync(string userName, CancellationToken cancellationToken)
        {
            var hashedUserName = _hasher.CreateHash(userName, CryptoStoreSimulator.KEYNAME_USERNAME, BaseCryptographyItem.HashAlgorithm.SHA2_512);
            var user = _dbContext.Users.SingleOrDefault(u => u.UserName == hashedUserName);

            if (user != null)
            {
                user.UserName = _cryptoStore.GetUserName(user.Id);
                user.Email = _cryptoStore.GetUserEmail(user.Id);
                user.NormalizedUserName = _cryptoStore.GetNormalizedUserName(user.Id);
                user.NormalizedEmail = _cryptoStore.GetNormalizedUserEmail(user.Id);
                user.PhoneNumber = _cryptoStore.GetPhoneNumber(user.Id);

                _dbContext.Entry(user).State = EntityState.Detached;
            }

            return Task.FromResult(user);
        }

        public DateTime? GetPasswordExpiration(IdentityUser user)
        {
            var latest = _dbContext.PasswordHistory.OrderByDescending(h => h.CreatedOn).FirstOrDefault(h => h.UserId == user.Id);

            if (latest == null)
                return null;
            else
                return latest.ExpiresOn;
        }

        public bool GetNewPasswordIsValid(IdentityUser user, string password)
        {
            //Hard-coded minimum of six unique passwords
            var history = _dbContext.PasswordHistory.Where(h => h.UserId == user.Id).OrderByDescending(u => u.CreatedOn).Take(5);

            if (history.Count() == 0)
                return true;

            var count = 1;
            foreach (var item in history)
            {
                //For simplicity, hard-coding the validity check
                //Cannot reuse one of the last 3 passwords
                //Or one used in the last 6 months
                if (count > 3 && item.CreatedOn < DateTime.UtcNow.AddMonths(6))
                    return true;

                //We'll rehash the password each time 
                if (_hasher.MatchesHash(password, item.PasswordHash))
                    return false;

                count++;
            }

            return true;
        }

        public Task AddPasswordHistoryItem(IdentityUser user, string password)
        {
            var passwordHistory = new PasswordHistory();
            passwordHistory.UserId = user.Id;
            passwordHistory.PasswordHash = _passwordHasher.HashPassword(user, password);
            passwordHistory.CreatedOn = DateTime.UtcNow;

            //This configuration can/should be moved to a service
            passwordHistory.ExpiresOn = DateTime.UtcNow.AddMonths(3);

            _dbContext.PasswordHistory.Add(passwordHistory);
            _dbContext.SaveChanges();

            return Task.CompletedTask;
        }
        #endregion

        #region IUserRoleStore
        public Task AddToRoleAsync(IdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            //TODO: Make sure user isn't already in role
            var role = _dbContext.Roles.Single(r => r.Name == roleName);
            var mapping = new IdentityUserRole<string>();

            mapping.UserId = user.Id;
            mapping.RoleId = role.Id;

            _dbContext.UserRoles.Add(mapping);
            _dbContext.SaveChanges();

            return Task.CompletedTask;
        }

        public Task<IList<string>> GetRolesAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            var roleNames = new List<string>();

            foreach (var roleMapping in _dbContext.UserRoles.Where(ur => ur.UserId == user.Id))
            {
                roleNames.Add(_dbContext.Roles.Single(r => r.Id == roleMapping.RoleId).Name);
            }

            IList<string> rolesAsIList = roleNames;
            return Task.FromResult(rolesAsIList);
        }

        public Task<IList<IdentityUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            var roleId = _dbContext.Roles.Single(r => r.Name == roleName).Id;

            var mappings = _dbContext.UserRoles.Where(ur => ur.RoleId == roleId);

            IList<IdentityUser> users = new List<IdentityUser>();

            foreach (var map in mappings)
            {
                users.Add(_dbContext.Users.Single(u => u.Id == map.UserId));
            }

            return Task.FromResult(users);
        }

        public Task<bool> IsInRoleAsync(IdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            var role = _dbContext.Roles.Single(r => r.Name == roleName);

            var mapping = _dbContext.UserRoles.SingleOrDefault(ur => ur.RoleId == role.Id && ur.UserId == user.Id);

            var isInRole = mapping != null;

            return Task.FromResult(isInRole);
        }

        public Task RemoveFromRoleAsync(IdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            var role = _dbContext.Roles.Single(r => r.Name == roleName);

            var mapping = _dbContext.UserRoles.SingleOrDefault(ur => ur.UserId == user.Id && ur.RoleId == role.Id);

            if (mapping != null)
            {
                _dbContext.UserRoles.Remove(mapping);
                _dbContext.SaveChanges();
            }

            return Task.CompletedTask;
        }
        #endregion

        #region IUserLockoutStore
        public Task<int> GetAccessFailedCountAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(true);
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.LockoutEnd);
        }

        public Task<int> IncrementAccessFailedCountAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            user.AccessFailedCount = 0;
            return Task.CompletedTask;
        }

        public Task SetLockoutEnabledAsync(IdentityUser user, bool enabled, CancellationToken cancellationToken)
        {
            //This should be enabled for all users, so just return here
            return Task.CompletedTask;
        }

        public Task SetLockoutEndDateAsync(IdentityUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
        #endregion

        #region IUserClaimStore
        public Task AddClaimsAsync(IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            foreach (var claim in claims)
            {
                var newClaim = new IdentityUserClaim<string>();

                newClaim.UserId = user.Id;
                newClaim.ClaimType = claim.Type;
                newClaim.ClaimValue = claim.Value;

                _dbContext.UserClaims.Add(newClaim);
            }

            _dbContext.SaveChanges();

            return Task.CompletedTask;
        }

        public Task<IList<Claim>> GetClaimsAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            IList<Claim> claims = new List<Claim>();

            var dbClaims = _dbContext.UserClaims.Where(uc => uc.UserId == user.Id);

            foreach (var claim in dbClaims)
            {
                var newClaim = new Claim(claim.ClaimType, claim.ClaimValue);
                claims.Add(newClaim);
            }

            return Task.FromResult(claims);
        }

        public Task<IList<IdentityUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            IList<IdentityUser> users = new List<IdentityUser>();

            var dbClaims = _dbContext.UserClaims.Where(uc => uc.ClaimType == claim.Type && uc.ClaimValue == claim.Value);

            foreach (var uc in dbClaims)
            {
                users.Add(_dbContext.Users.Single(u => u.Id == uc.UserId));
            }

            return Task.FromResult(users);
        }

        public Task RemoveClaimsAsync(IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            foreach (var c in claims)
            {
                var dbClaim = _dbContext.UserClaims.Single(uc => uc.UserId == user.Id && uc.ClaimType == c.Type && uc.ClaimValue == c.Value);

                _dbContext.UserClaims.Remove(dbClaim);
            }

            _dbContext.SaveChanges();

            return Task.CompletedTask;
        }

        public Task ReplaceClaimAsync(IdentityUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            var dbClaim = _dbContext.UserClaims.Single(uc => uc.UserId == user.Id && uc.ClaimType == claim.Type && uc.ClaimValue == claim.Value);

            dbClaim.ClaimType = newClaim.Type;
            dbClaim.ClaimValue = newClaim.Value;

            _dbContext.SaveChanges();

            return Task.CompletedTask;
        }
        #endregion

        #region IUserLoginStore
        public Task AddLoginAsync(IdentityUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            var loginInfo = new IdentityUserLogin<string>();

            loginInfo.LoginProvider = login.LoginProvider;
            loginInfo.ProviderDisplayName = login.ProviderDisplayName;
            loginInfo.ProviderKey = login.ProviderKey;
            loginInfo.UserId = user.Id;

            _dbContext.UserLogins.Add(loginInfo);
            _dbContext.SaveChanges();

            return Task.CompletedTask;
        }

        public Task RemoveLoginAsync(IdentityUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var info = _dbContext.UserLogins.Single(ul => ul.UserId == user.Id && ul.LoginProvider == loginProvider && ul.ProviderKey == providerKey);

            _dbContext.UserLogins.Remove(info);
            _dbContext.SaveChanges();

            return Task.CompletedTask;
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            IList<UserLoginInfo> info = new List<UserLoginInfo>();

            info = _dbContext.UserLogins.Where(ul => ul.UserId == user.Id).Select(ul => new UserLoginInfo(ul.LoginProvider, ul.ProviderKey, ul.ProviderDisplayName)).ToList();

            return Task.FromResult(info);
        }

        public Task<IdentityUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            IdentityUser user = null;

            var loginInfo = _dbContext.UserLogins.SingleOrDefault(ul => ul.LoginProvider == loginProvider && ul.ProviderKey == providerKey);
            if (loginInfo != null)
            {
                user = _dbContext.Users.SingleOrDefault(u => u.Id == loginInfo.UserId);

                if (user != null)
                { 
                    user.UserName = _cryptoStore.GetUserName(user.Id);
                    user.Email = _cryptoStore.GetUserEmail(user.Id);
                    user.NormalizedUserName = _cryptoStore.GetNormalizedUserName(user.Id);
                    user.NormalizedEmail = _cryptoStore.GetNormalizedUserEmail(user.Id);
                    user.PhoneNumber = _cryptoStore.GetPhoneNumber(user.Id);  
                    
                    _dbContext.Entry(user).State = EntityState.Detached;
                }
            }

            return Task.FromResult(user);
        }
        #endregion
    }
}
