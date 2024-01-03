using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Crypto.Digests;
using System.Text;
using System.Threading.Tasks;

namespace PoC_CipherAlgoritms.SHA3Impl
{
    public class MySHA3
    {
        public static byte[] ComputeSHA3Hash(string data)
        {
            var sha3 = new Sha3Digest(256);
            
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            sha3.BlockUpdate(dataBytes, 0, dataBytes.Length);

            byte[] hash = new byte[sha3.GetDigestSize()];
            sha3.DoFinal(hash, 0);

            return hash;
            
        }
    }
}
