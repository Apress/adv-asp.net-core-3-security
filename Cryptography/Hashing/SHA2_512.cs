using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Cryptography.Hashing
{
    public class SHA2_512 : BaseCryptographyItem
    {
        public string Hash(string plainText, string salt, bool saveSaltInResult)
        {
            var fullText = string.Concat(plainText, salt);
            var data = Encoding.UTF8.GetBytes(fullText);

            //Best hash in native .NET
            using (SHA512 sha = new SHA512Managed())
            {
                var hashBytes = sha.ComputeHash(data);
                var asString = ByteArrayToString(hashBytes);

                if (saveSaltInResult)
                    return string.Format("[{0}]{1}{2}", (int)HashAlgorithm.SHA2_512, salt, asString);
                else
                    return string.Format("[{0}]{1}", (int)HashAlgorithm.SHA2_512, asString);
            }
        }

        public string Hash_PBKDF2(string plainText, string salt, bool saveSaltInResult)
        {
            var saltAsBytes = Encoding.ASCII.GetBytes(salt);

            string hashed = ByteArrayToString(KeyDerivation.Pbkdf2(
                password: plainText,
                salt: saltAsBytes,
                prf: KeyDerivationPrf.HMACSHA512, //.NET 3.1 uses HMACSHA256 here
                iterationCount: 100000, //.NET 3.1 uses 10,000 iterations here
                numBytesRequested: 64)); //.NET 3.1 uses 32 bytes here

            if (saveSaltInResult)
                return string.Format("[{0}]{1}{2}", (int)HashAlgorithm.PBKDF2_SHA512, salt, hashed);
            else
                return string.Format("[{0}]{1}", (int)HashAlgorithm.PBKDF2_SHA512, hashed);
        }
    }
}
