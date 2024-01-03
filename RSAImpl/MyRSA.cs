using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PoC_CipherAlgoritms.RSAImpl
{
    public class MyRSA
    {
        public static byte[] EncryptStringToBytes_RSA(string plainText, RSAParameters publicKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);
                return rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.Pkcs1);
            }
        }

        public static string DecryptStringFromBytes_RSA(byte[] cipherText, RSAParameters privateKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);
                byte[] decryptedBytes = rsa.Decrypt(cipherText, RSAEncryptionPadding.Pkcs1);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
    }
}
