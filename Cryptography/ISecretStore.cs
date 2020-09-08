using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Cryptography
{
    public interface ISecretStore
    {
        string GetKey(string keyName, int keyIndex);
        string GetSalt(string saltName);
    }
}
