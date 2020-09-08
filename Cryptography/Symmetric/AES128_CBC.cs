using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Cryptography.Symmetric
{
    public class AES128_CBC : BaseCryptographyItem
    {
        private const int _blockSizeInBytes = 16;

        public string Encrypt(string plainText, string keyString, EncryptionAlgorithm algorithm, int keyIndex)
        {
            byte[] encrypted;
            var keyBytes = HexStringToByteArray(keyString);
            var iv = CreateRandomByteArray(_blockSizeInBytes);

            using (Rijndael rijndael = Rijndael.Create())
            {
                //Store in Hardware Security Module (HSM) if you can
                rijndael.Key = keyBytes;
                rijndael.Padding = PaddingMode.PKCS7;
                rijndael.Mode = CipherMode.CBC;
                rijndael.IV = iv;

                ICryptoTransform encryptor = rijndael.CreateEncryptor(rijndael.Key, rijndael.IV);

                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(cryptStream))
                        {
                            writer.Write(plainText);
                        }

                        encrypted = memStream.ToArray();
                    }
                }
            }

            var asString = ByteArrayToString(encrypted);
            var ivAsString = ByteArrayToString(iv);

            return $"[{(int)algorithm},{keyIndex}]{ivAsString}{asString}";
        }

        public string Decrypt(string cipherText, string key, EncryptionAlgorithm algorithm)
        {
            string plaintext = null;
            var keyBytes = HexStringToByteArray(key);

            var ivString = cipherText.Substring(0, _blockSizeInBytes * 2);
            var ivBytes = HexStringToByteArray(ivString);

            var cipherNoIV = cipherText.Substring(_blockSizeInBytes * 2, cipherText.Length - _blockSizeInBytes * 2);
            var cipherBytes = HexStringToByteArray(cipherNoIV);

            using (Rijndael rijndael = Rijndael.Create())
            {
                rijndael.Key = keyBytes;
                rijndael.Padding = PaddingMode.PKCS7;
                rijndael.Mode = CipherMode.CBC;
                rijndael.IV = ivBytes;

                ICryptoTransform decryptor = rijndael.CreateDecryptor(rijndael.Key, rijndael.IV);

                using (MemoryStream memStream = new MemoryStream(cipherBytes))
                {
                    using (CryptoStream cryptStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(cryptStream))
                        {
                            plaintext = reader.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}
