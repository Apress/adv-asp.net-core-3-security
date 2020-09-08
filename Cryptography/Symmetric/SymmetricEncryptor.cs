using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Cryptography.Symmetric
{
    public class SymmetricEncryptor : BaseCryptographyItem, ISymmetricEncryptor
    {
        private EncryptionAlgorithm _defaultAlgorithm = EncryptionAlgorithm.AES128_CBC;
        private readonly int _defaultKeyIndex;
        private readonly ISecretStore _secretStore;

        public SymmetricEncryptor(IConfiguration config, ISecretStore secretStore)
        {
            _defaultKeyIndex = config.GetValue<int>("AppSettings:KeyIndex");
            _secretStore = secretStore;
        }

        public string EncryptString(string plainText, string keyName)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("PlainText cannot be empty");
            if (keyName == null || keyName.Length <= 0)
                throw new ArgumentNullException("Key Name cannot be empty");

            var keyString = _secretStore.GetKey(keyName, _defaultKeyIndex);

            switch (_defaultAlgorithm)
            {
                case EncryptionAlgorithm.AES128_CBC:
                    var aes128 = new AES128_CBC();
                    return aes128.Encrypt(plainText, keyString, _defaultAlgorithm, _defaultKeyIndex);
                case EncryptionAlgorithm.AES128_CTR:
                case EncryptionAlgorithm.AES256_CTR:
                    var aesCTR = new AES_CTR();
                    return aesCTR.Encrypt(plainText, keyString, _defaultAlgorithm, _defaultKeyIndex);
                default:
                    throw new NotImplementedException(_defaultAlgorithm.ToString());
            }
        }

        public string DecryptString(string cipherText, string keyName)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (keyName == null || keyName.Length <= 0)
                throw new ArgumentNullException("Key Name");

            int? algorithmAsInt = null;
            int? keyIndex = null;
            string plainCipherText = null;
            GetAlgorithm(cipherText, out algorithmAsInt, out keyIndex, out plainCipherText);

            if (!algorithmAsInt.HasValue)
                throw new InvalidOperationException("Cannot find an algorithm for encrypted string");

            var algorithm = (EncryptionAlgorithm)algorithmAsInt.Value;

            var keyString = _secretStore.GetKey(keyName, keyIndex.Value);

            switch (algorithm)
            {
                case EncryptionAlgorithm.AES128_CBC:
                    var aes128 = new AES128_CBC();
                    return aes128.Decrypt(plainCipherText, keyString, algorithm);
                case EncryptionAlgorithm.AES128_CTR:
                case EncryptionAlgorithm.AES256_CTR:
                    var aesCTR = new AES_CTR();
                    return aesCTR.Decrypt(plainCipherText, keyString, algorithm);
                default:
                    throw new InvalidOperationException($"Cannot decrypt cipher text with algorithm {algorithm}");
            }
        }
    }
}
