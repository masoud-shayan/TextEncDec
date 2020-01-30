using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptAndDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Enter a message that you want to encrypt: ");
            string message = Console.ReadLine();
            Console.WriteLine("Enter a password: ");
            string password = Console.ReadLine();
            string cryptoText = Protector.Encrypt(message, password);
            Console.WriteLine($"Encrypted text: {cryptoText}");
            Console.WriteLine("Enter the password: ");
            string password2 = Console.ReadLine();
            try
            {
                string clearText = Protector.Decrypt(cryptoText, password2);
                Console.WriteLine($"Decrypted text: {clearText}");
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine("{0}\nMore details: {1}", "You entered the wrong password!", ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Non-cryptographic exception: {0}, {1}", ex.GetType().Name, ex.Message);
            }
        }
    }

    public static class Protector
    {
        private static readonly byte[] salt = Encoding.Unicode.GetBytes("Masoudis11");

        private static readonly int iterations = 2000;
        public static string Encrypt(string plainText, string password)
        {
            byte[] encryptedBytes;
            byte[] plainBytes = Encoding.Unicode.GetBytes(plainText);
            var aes = Aes.Create();
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = pbkdf2.GetBytes(32);
            aes.IV = pbkdf2.GetBytes(16);
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plainBytes, 0, plainBytes.Length);
                }

                encryptedBytes = ms.ToArray();
            }

            return Convert.ToBase64String(encryptedBytes);
        }

        public static string Decrypt(string cryptoText, string password)
        {
            byte[] plainBytes;
            byte[] cryptoBytes = Convert.FromBase64String(cryptoText);
            var aes = Aes.Create();
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = pbkdf2.GetBytes(32);
            aes.IV = pbkdf2.GetBytes(16);
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cryptoBytes, 0, cryptoBytes.Length);
                }

                plainBytes = ms.ToArray();
            }

            return Encoding.Unicode.GetString(plainBytes);
        }
    }
}