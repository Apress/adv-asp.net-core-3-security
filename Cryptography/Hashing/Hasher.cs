using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Cryptography.Hashing
{
    public class Hasher : BaseCryptographyItem, IHasher, IPasswordHasher<IdentityUser>
    {
        private const int SaltLength = 32;
        private readonly ISecretStore _secretStore;

        public Hasher(ISecretStore secretStore)
        {
            _secretStore = secretStore;
        }

        /// <summary>
        /// Creates a hash with the specified algorithm and saves the salt in the ciphertext
        /// </summary>
        /// <param name="plainText">Plain text</param>
        /// <param name="algorithm">Algorithm to use</param>
        /// <returns>Ciphertext with salt</returns>
        public string CreateHash(string plainText, HashAlgorithm algorithm)
        {
            var salt = CreateRandomString(SaltLength);
            return CreateHash(plainText, salt, algorithm, true);
        }

        public string CreateHash(string plainText, string saltName, HashAlgorithm algorithm)
        {
            var salt = _secretStore.GetSalt(saltName);
            return CreateHash(plainText, salt, algorithm, false);
        }

        public bool MatchesHash(string plainText, string hash)
        {
            string trimmedHash = "";
            string salt = "";
            int? algorithmAsInt = 0;
            int? hashIndex = 0;

            GetAlgorithm(hash, out algorithmAsInt, out hashIndex, out trimmedHash, out salt);

            if (!algorithmAsInt.HasValue)
                return false;

            var hashAlgorithm = (HashAlgorithm)algorithmAsInt.Value;
            var hashed = CreateHash(plainText, salt, hashAlgorithm, true);
            return hashed == hash;
        }

        private string CreateHash(string plainText, string salt, HashAlgorithm algorithm, bool saveSaltInResult)
        {
            var hash = "";

            switch (algorithm)
            {
                case HashAlgorithm.SHA2_512:
                    var sha2 = new SHA2_512();
                    hash = sha2.Hash(plainText, salt, saveSaltInResult);
                    break;
                case HashAlgorithm.PBKDF2_SHA512:
                    var sha2_KDF = new SHA2_512();
                    hash = sha2_KDF.Hash_PBKDF2(plainText, salt, saveSaltInResult);
                    break;
                case HashAlgorithm.SHA3_512:
                    var sha3 = new SHA3();
                    hash = sha3.Hash(plainText, salt, saveSaltInResult, 512);
                    break;
                default:
                    throw new NotImplementedException($"Hash algorithm {algorithm.ToString()} has not been implemented");
            }

            return hash;
        }

        public string HashPassword(IdentityUser user, string password)
        {
            return CreateHash(password, HashAlgorithm.PBKDF2_SHA512);
        }

        public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword)
        {
            var isMatch = MatchesHash(providedPassword, hashedPassword);

            if (isMatch)
                return PasswordVerificationResult.Success;
            else
                return PasswordVerificationResult.Failed;
        }

        private void GetAlgorithm(string cipherText, out int? algorithm, out int? keyIndex, out string trimmedCipherText, out string salt)
        {
            GetAlgorithm(cipherText, out algorithm, out keyIndex, out trimmedCipherText);

            if (algorithm.HasValue && trimmedCipherText.Length > SaltLength)
            {
                salt = trimmedCipherText.Substring(0, SaltLength);
                trimmedCipherText = trimmedCipherText.Substring(SaltLength);
            }
            else
            {
                salt = null;
            }
        }
    }
}
