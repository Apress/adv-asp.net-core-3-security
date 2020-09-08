using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Text;

namespace Advanced.Security.V3.Cryptography.Hashing
{
    public class SHA3 : BaseCryptographyItem
    {
        public string Hash(string valueToHash, string salt, bool saveSaltInResult, int bitLength)
        {
            var fullText = string.Concat(valueToHash, salt);
            var data = Encoding.UTF8.GetBytes(fullText);

            var sha3 = new Sha3Digest(bitLength);
            var hashedBytes = new byte[sha3.GetDigestSize()];
            var toHashAsBytes = Encoding.ASCII.GetBytes(valueToHash);

            sha3.BlockUpdate(toHashAsBytes, 0, toHashAsBytes.Length);
            sha3.DoFinal(hashedBytes, 0);

            var asString = ByteArrayToString(hashedBytes);

            var algorithm = 0;

            if (bitLength == 512)
                algorithm = (int)HashAlgorithm.SHA3_512;
            else
                throw new NotImplementedException($"Cannot find a HashAlgorithm for bit length: {bitLength}");

            if (saveSaltInResult)
                return string.Format("[{0}]{1}{2}", algorithm, salt, asString);
            else
                return string.Format("[{0}]{1}", algorithm, asString);
        }
    }
}
