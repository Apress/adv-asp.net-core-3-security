using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Advanced.Security.V3.Cryptography.Hashing;
using Advanced.Security.V3.Cryptography.Symmetric;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Advanced.Security.V3.Controllers
{
    public class CryptographyController : Controller
    {
        private readonly IHasher _hasher;
        private readonly ISymmetricEncryptor _encryptor;

        public CryptographyController(IHasher hasher, ISymmetricEncryptor encryptor)
        {
            _hasher = hasher;
            _encryptor = encryptor;
        }

        public IActionResult Index()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult Hash(string value)
        {
            if (string.IsNullOrEmpty(value))
                value = "password";

            var hashed = new List<string>();

            hashed.Add(_hasher.CreateHash(value, "EMPTY_SALT", V3.Cryptography.BaseCryptographyItem.HashAlgorithm.SHA2_512));
            hashed.Add(_hasher.CreateHash(value, "EMPTY_SALT", V3.Cryptography.BaseCryptographyItem.HashAlgorithm.SHA3_512));
            hashed.Add(_hasher.CreateHash(value, "EMPTY_SALT", V3.Cryptography.BaseCryptographyItem.HashAlgorithm.PBKDF2_SHA512));

            return View(hashed);
        }

        [AllowAnonymous]
        public IActionResult Encrypt(string value)
        {
            if (string.IsNullOrEmpty(value))
                value = "password";

            var values = new List<string>();

            var encrypted = _encryptor.EncryptString(value, "AspNetUsers_UserName");
            var decrypted = _encryptor.DecryptString(encrypted, "AspNetUsers_UserName");

            values.Add(encrypted);
            values.Add(decrypted);

            return View(values);
        }

    }
}
