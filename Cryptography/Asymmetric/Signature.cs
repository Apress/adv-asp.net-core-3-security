using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Advanced.Security.V3.Cryptography.Asymmetric
{
    public static class Signature
    {
        public enum SignatureAlgorithm
        {
            RSA2048SHA512 = 1
        }

        public static string CreateSignature(string textToSign, string keyInXMLFormat)
        {
            if (textToSign == null || textToSign.Length <= 0)
                throw new ArgumentNullException("textToSign cannot be null");
            if (keyInXMLFormat == null || keyInXMLFormat.Length <= 0)
                throw new ArgumentNullException("keyInXMLFormat cannot be null");

            return CreateSignatureRSA2048SHA512(textToSign, keyInXMLFormat);
        }

        private static string CreateSignatureRSA2048SHA512(string plainText, string keyInXMLFormat)
        {
            string asString;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                rsa.ImportParametersFromXmlString(keyInXMLFormat);

                byte[] hashBytes;

                using (SHA512 sha = new SHA512Managed())
                {
                    var data = Encoding.UTF8.GetBytes(plainText);
                    hashBytes = sha.ComputeHash(data);
                }

                var formatter = new RSAPKCS1SignatureFormatter(rsa);
                formatter.SetHashAlgorithm("SHA512");
                var signedAsBytes = formatter.CreateSignature(hashBytes);

                asString = ByteArrayToString(signedAsBytes);
            }

            return "[" + ((int)SignatureAlgorithm.RSA2048SHA512).ToString() + "]" + asString;
        }

        public static bool VerifySignature(string textToVerify, string oldSignature, string keyInXMLFormat)
        {
            if (textToVerify == null || textToVerify.Length <= 0)
                throw new ArgumentNullException("textToVerify cannot be null");
            if (oldSignature == null || oldSignature.Length <= 0)
                throw new ArgumentNullException("oldSignature cannot be null");
            if (keyInXMLFormat == null || keyInXMLFormat.Length <= 0)
                throw new ArgumentNullException("keyInXMLFormat");

            int? algorithm = null;
            string signatureNoPrefix = null;
            GetAlgorithm(oldSignature, out algorithm, out signatureNoPrefix);

            if (!algorithm.HasValue)
                throw new InvalidOperationException("Cannot find an algorithm for encrypted string");

            if (algorithm.Value == (int)SignatureAlgorithm.RSA2048SHA512)
                return VerifySignatureRSA2048SHA512(textToVerify, signatureNoPrefix, keyInXMLFormat);
            else
                throw new InvalidOperationException($"Cannot decrypt cipher text with algorithm { algorithm }");
        }

        private static Boolean VerifySignatureRSA2048SHA512(string textToVerify, string oldSignature, string keyInXMLFormat)
        {
            Boolean result;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                byte[] hashBytes;

                using (SHA512 sha = new SHA512Managed())
                {
                    var data = Encoding.UTF8.GetBytes(textToVerify);
                    hashBytes = sha.ComputeHash(data);
                }

                var oldSignatureAsBytes = HexStringToByteArray(oldSignature);

                rsa.ImportParametersFromXmlString(keyInXMLFormat);
                var formatter = new RSAPKCS1SignatureDeformatter(rsa);
                formatter.SetHashAlgorithm("SHA512");
                result = formatter.VerifySignature(hashBytes, oldSignatureAsBytes);
            }

            return result;
        }

        private static byte[] HexStringToByteArray(string stringInHexFormat)
        {
            return Enumerable.Range(0, stringInHexFormat.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(stringInHexFormat.Substring(x, 2), 16))
                     .ToArray();
        }

        private static string ByteArrayToString(byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (var b in bytes)
                sb.Append(b.ToString("X2"));

            return sb.ToString();
        }

        private static void GetAlgorithm(string cipherText, out int? algorithm, out string trimmedCipherText)
        {
            if (cipherText.Length > 3 && cipherText[0] == '[')
            {
                var foundAlgorithm = 0;
                var storedAlgorithm = cipherText.Substring(1, cipherText.IndexOf(']'));

                if (!int.TryParse(cipherText[1].ToString(), out foundAlgorithm))
                    algorithm = null;
                else
                    algorithm = foundAlgorithm;

                trimmedCipherText = cipherText.Substring(cipherText.IndexOf(']') + 1);
            }
            else
            {
                algorithm = null;
                trimmedCipherText = cipherText;
            }
        }
    }

    public static class XmlImportExport
    {
        public static void ImportParametersFromXmlString(this RSA rsa, string xmlString)
        {
            var parameters = new RSAParameters();

            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (!xmlDoc.DocumentElement.Name.Equals("key"))
                throw new NotSupportedException("Format unknown");

            foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
            {
                switch (node.Name)
                {
                    case "modulus":
                        parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText));
                        break;
                    case "exponent":
                        parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText));
                        break;
                    case "p":
                        parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText));
                        break;
                    case "q":
                        parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText));
                        break;
                    case "dp":
                        parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText));
                        break;
                    case "dq":
                        parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText));
                        break;
                    case "inverseq":
                        parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText));
                        break;
                    case "d":
                        parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText));
                        break;
                    default:
                        throw new InvalidOperationException($"Cannot find parameter for {node.Name}");
                }
            }

            rsa.ImportParameters(parameters);
        }

        public static string SendParametersToXmlString(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            return string.Format("<key><modulus>{0}</modulus><exponent>{1}</exponent><p>{2}</p><q>{3}</q><dp>{4}</dp><dq>{5}</dq><inverseq>{6}</inverseq><d>{7}</d></key>",
                parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }
    }
}
