using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Cryptography
{
    public class SecretStore : ISecretStore
    {
        //FOR TESTING/DEMONSTRATION ONLY!!!
        //KEYS SHOULD BE STORED SECURELY, NOT HARD-CODED IN THE APP!!!
        public string GetKey(string keyName, int keyIndex)
        {
            //Use Key Index to rotate keys if needed

            if (keyIndex == 1)
            {
                switch (keyName)
                {
                    case CryptoStoreSimulator.KEYNAME_USERNAME:
                        return "1F03B0AE4DECEA303DBA5C70B96F06CE";
                    case CryptoStoreSimulator.KEYNAME_EMAIL:
                        return "E9D03B780C0BD16907E8F586033C0DAE";
                    case CryptoStoreSimulator.KEYNAME_NORMALIZED_USERNAME:
                        return "C4618965275F268175D42F6D9143A935";
                    case CryptoStoreSimulator.KEYNAME_NORMALIZED_EMAIL:
                        return "80FED0C26824D42BD9CD85B57C107204";
                    case CryptoStoreSimulator.KEYNAME_PHONE:
                        return "1969583C833B246BE394176FDA7A9E21";
                    default:
                        throw new NotImplementedException($"No key for {keyName} found");
                }
            }
            else if (keyIndex == 2)
            {
                switch (keyName)
                {
                    case CryptoStoreSimulator.KEYNAME_USERNAME:
                        return "5F88F4C660B133E472A1B2FC95FC960B";
                    case CryptoStoreSimulator.KEYNAME_EMAIL:
                        return "6096A90685B8FEEEC0267CA930E6B049";
                    case CryptoStoreSimulator.KEYNAME_NORMALIZED_USERNAME:
                        return "1969583C833B246BE394176FDA7A9E21";
                    case CryptoStoreSimulator.KEYNAME_NORMALIZED_EMAIL:
                        return "B2A1F652A46B89CBBCD1CCD4DF4FC4BB";
                    default:
                        throw new NotImplementedException($"No key for {keyName} found");
                }
            }
            else
                throw new NotImplementedException($"Cannot find keys for key index: {keyIndex}");
        }

        //Hard-coded salts are a terrible idea! These are here for demonstration purposes only!!!
        public string GetSalt(string saltName)
        {
            if (saltName == CryptoStoreSimulator.KEYNAME_USERNAME)
                return "4129F57F34DE621C41931AB3EC0E31B1EA742E8A454B1570F47AB77C538EEA9D";
            else if (saltName == CryptoStoreSimulator.KEYNAME_EMAIL)
                return "FFA5954D477572D8A07A89D61A983AED953680FCC093FDDF4FFCF4FBD9993382";
            else if (saltName == CryptoStoreSimulator.KEYNAME_NORMALIZED_USERNAME)
                return "98D0AA51A00787B709FC8D7D1B5038DFE57CB531AF83DD53FF0CE531D9638EBD";
            else if (saltName == CryptoStoreSimulator.KEYNAME_NORMALIZED_EMAIL)
                return "58AED901C7DC072F998FED243A95E89A77F3890EE9D1DC33C6B2DAB9983A34B5";
            else if (saltName == CryptoStoreSimulator.KEYNAME_PHONE)
                return "1969583C833B246BE394176FDA7A9E21B2A1F652A46B89CBBCD1CCD4DF4FC4BB";
            else if (saltName == "EMPTY_SALT") //For verification only!
                return "";
            else
                throw new NotImplementedException($"Cannot find salt for: {saltName}");
        }
    }
}
