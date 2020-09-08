using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Cryptography
{
    public abstract class BaseCryptographyItem
    {
        public enum HashAlgorithm
        {
            SHA2_512 = 1,
            PBKDF2_SHA512 = 2,
            SHA3_512 = 3
        }

        public enum EncryptionAlgorithm
        {
            AES128_CBC = 1,
            AES128_CTR = 3,
            AES256_CTR = 4
        }

        protected byte[] HexStringToByteArray(string stringInHexFormat)
        {
            return Enumerable.Range(0, stringInHexFormat.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(stringInHexFormat.Substring(x, 2), 16))
                     .ToArray();
        }

        protected string ByteArrayToString(byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (var b in bytes)
                sb.Append(b.ToString("X2"));

            return sb.ToString();
        }

        protected string CreateRandomString(int length)
        {
            var rng = new RNGCryptoServiceProvider();
            var buffer = new byte[length / 2];

            rng.GetBytes(buffer);
            return BitConverter.ToString(buffer).Replace("-", "");
        }

        protected void GetAlgorithm(string cipherText, out int? algorithm, out int? keyIndex, out string trimmedCipherText)
        {
            //For now, fail open and let the calling method handle issues
            //In greenfield systems, consider failing closed here
            algorithm = null;
            keyIndex = null;
            trimmedCipherText = cipherText;

            if (cipherText.Length <= 5 || cipherText[0] != '[')
                return;

            var foundAlgorithm = 0;
            var foundKeyIndex = 0;

            var cipherInfo = cipherText.Substring(1, cipherText.IndexOf(']') - 1).Split(",");

            //if (cipherInfo.Length != 2)
            //    return;

            if (int.TryParse(cipherInfo[0], out foundAlgorithm))
                algorithm = foundAlgorithm;


            if (cipherInfo.Length == 2 && int.TryParse(cipherInfo[1], out foundKeyIndex))
                keyIndex = foundKeyIndex;

            trimmedCipherText = cipherText.Substring(cipherText.IndexOf(']') + 1);
        }

        protected byte[] CreateRandomByteArray(int length)
        {
            var rng = new RNGCryptoServiceProvider();
            var buffer = new byte[length];

            rng.GetBytes(buffer);
            return buffer;
        }
    }
}
