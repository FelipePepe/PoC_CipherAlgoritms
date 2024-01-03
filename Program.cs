using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using PoC_CipherAlgoritms.AESImpl;
using PoC_CipherAlgoritms.ECCImpl;
using PoC_CipherAlgoritms.RSAImpl;
using PoC_CipherAlgoritms.SHA3Impl;

namespace PoC_CipherAlgoritms
{
    internal class Program
    {
        static void Main(string[] args)
        {
            new Program();
        }

        public Program()
        {
            PoC_AES();
            PoC_RSA();
            PoC_ECC();
            PoC_SHA3();
            Console.Read();
        }

        private void PoC_AES()
        {
            string plainText = "Hello, AES!";
            using (Aes aesAlg = Aes.Create())
            {
                byte[] key = aesAlg.Key;
                byte[] iv = aesAlg.IV;

                // Encrypt
                byte[] encrypted = MyAES.EncryptStringToBytes_Aes(plainText, key, iv);

                // Decrypt
                string decrypted = MyAES.DecryptStringFromBytes_Aes(encrypted, key, iv);

                Console.WriteLine($"Original: {plainText}");
                Console.WriteLine($"Encrypted: {BitConverter.ToString(encrypted)}");
                Console.WriteLine($"Decrypted: {decrypted}");
            }
        }

        private void PoC_RSA()
        {
            string plainText = "Hello, RSA!";
            using (RSA rsa = RSA.Create())
            {
                RSAParameters publicKey = rsa.ExportParameters(false);
                RSAParameters privateKey = rsa.ExportParameters(true);

                // Encrypt
                byte[] encrypted = MyRSA.EncryptStringToBytes_RSA(plainText, publicKey);

                // Decrypt
                string decrypted = MyRSA.DecryptStringFromBytes_RSA(encrypted, privateKey);

                Console.WriteLine($"Original: {plainText}");
                Console.WriteLine($"Encrypted: {BitConverter.ToString(encrypted)}");
                Console.WriteLine($"Decrypted: {decrypted}");
            }
        }

        private void PoC_ECC()
        {
            

            using (ECDiffieHellmanCng alice = new ECDiffieHellmanCng())
            {
                alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                alice.HashAlgorithm = CngAlgorithm.Sha256;
                Alice.alicePublicKey = alice.PublicKey.ToByteArray();
                Bob bob = new Bob();
                CngKey bobKey = CngKey.Import(bob.bobPublicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] aliceKey = alice.DeriveKeyMaterial(bobKey);
                byte[] encryptedMessage = null;
                byte[] iv = null;
                Alice.Send(aliceKey, "Secret message", out encryptedMessage, out iv);
                bob.Receive(encryptedMessage, iv);
            }
        }

        private void PoC_SHA3()
        {
            string data = "Hello, SHA-3!";
            byte[] hash = MySHA3.ComputeSHA3Hash(data);

            Console.WriteLine($"Original: {data}");
            Console.WriteLine($"SHA-3 Hash: {BitConverter.ToString(hash)}");
        }
    }
}
