using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;
using System.Linq;

namespace jWtTokenWebApi.Auth
{
    public class AesEncryption
    {
        // Method to encrypt a string using AES
        public static string Encrypt(string plainText, string key)
        {
            // Generate an initialization vector (IV)
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(key);
                aesAlg.IV = aesAlg.Key.Take(16).ToArray();  // Ensure the IV is 16 bytes long

                // Create an encryptor to perform the stream transform
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            // Write the plain text to the stream
                            swEncrypt.Write(plainText);
                        }
                        byte[] encrypted = msEncrypt.ToArray();
                        // Return the encrypted bytes as a base64 string
                        return Convert.ToBase64String(encrypted);
                    }
                }
            }
        }

        // Method to decrypt a string using AES
        public static string Decrypt(string cipherText, string key)
        {
            // Convert the cipherText to bytes
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(key);
                aesAlg.IV = aesAlg.Key.Take(16).ToArray();  // Ensure the IV is 16 bytes long

                // Create a decryptor to perform the stream transform
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the stream and return as a string
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
