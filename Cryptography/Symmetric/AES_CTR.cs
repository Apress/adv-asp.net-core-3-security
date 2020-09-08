using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Cryptography.Symmetric
{
    public class AES_CTR : BaseCryptographyItem
    {
        private readonly int _iVSizeInBytes = 16;

        public string Encrypt(string text, string keyString, EncryptionAlgorithm algorithm, int keyIndex)
        {
            var aes = new RijndaelEngine();// AesEngine();
            var blockCipher = new SicBlockCipher(aes);
            var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

            var iv = CreateRandomByteArray(_iVSizeInBytes);

            var key = HexStringToByteArray(keyString);
            var keyParam = new KeyParameter(key);

            cipher.Init(true, new ParametersWithIV(keyParam, iv));
            var textAsBytes = Encoding.ASCII.GetBytes(text);

            var encryptedBytes = new byte[cipher.GetOutputSize(textAsBytes.Length)];
            var length = cipher.ProcessBytes(textAsBytes, encryptedBytes, 0);
            cipher.DoFinal(encryptedBytes, length);

            var encryptedAsString = ByteArrayToString(encryptedBytes);

            return $"[{((int)algorithm)},{keyIndex}]{ByteArrayToString(iv)}{encryptedAsString}";
        }

        public string Decrypt(string cipherText, string keyString, EncryptionAlgorithm algorithm)
        {
            var aes = new RijndaelEngine();
            var blockCipher = new SicBlockCipher(aes);
            var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

            var ivString = cipherText.Substring(0, _iVSizeInBytes * 2);
            var ivBytes = HexStringToByteArray(ivString);

            var cipherNoIV = cipherText.Substring(_iVSizeInBytes * 2, cipherText.Length - _iVSizeInBytes * 2);
            var cipherBytes = HexStringToByteArray(cipherNoIV);

            var key = HexStringToByteArray(keyString);
            var keyParam = new KeyParameter(key);

            cipher.Init(false, new ParametersWithIV(keyParam, ivBytes));

            var decryptedBytes = new byte[cipher.GetOutputSize(cipherBytes.Length)];
            var length = cipher.ProcessBytes(cipherBytes, 0, cipherBytes.Length, decryptedBytes, 0);

            cipher.DoFinal(decryptedBytes, length);

            return Encoding.ASCII.GetString(decryptedBytes);
        }
    }
}
