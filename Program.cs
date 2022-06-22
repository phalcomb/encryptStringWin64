using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace encryptString
{
    class Program
    {
        // Reading in any commandline parameters at startup

        static void Main(string[] args)
        {

            // Checking to see if any command line parameters were added to the commmand,
            // if not printing out instructions

            if (args.Length == 0)
	        {
                Console.WriteLine("\nInvalid Parameters\n");
                Console.WriteLine("Encrypt Useage: encryptString encrypt -s {0}stringValue{0}", Convert.ToChar(34));
                Console.WriteLine("Decrypt Useage: encryptString decrypt -s {0}stringValue{0}", Convert.ToChar(34));
                Console.WriteLine("\n");
                return;
	        }

            var key = "C498FD371940D49710867BE27345D3B9";   // Setting the encryption key for the program
            var content = "";                               // Declaring a variable to store the incoming text
            var encrypted = "";                             // Declaring a variable for encrypted text
            var decrypted = "";                             // Declaring a variable for decrypted text
            var command = args[0];                          // Storing commandline paramters in an arrary to process

            // Switch statement to process the commands

            switch (command)    
	        {
                // if the encrypt parameter was defined, then do this...
                    case "encrypt" when args.Length == 3 && args[1] == "-s":
                    content = args[2];
                    encrypted = EncryptString(content, key);
                    Console.WriteLine("\nEncrypted String: \n\n" + encrypted + "\n");
                    break;
                    
                // if the decrypt parameter was defined, then do this...
                    case "decrypt" when args.Length == 3 && args[1] == "-s":
                    encrypted = args[2];
                    decrypted = DecryptString(encrypted, key);
                    Console.WriteLine("\nDecrypted String: \n\n" + decrypted + "\n");
                    break;

                // if the commands don't make any sense then print out the instructions again
                    default:
                    Console.WriteLine("\nInvalid Parameters\n");
                    Console.WriteLine("Encrypt Useage: encryptString encrypt -s {0}stringValue{0}", Convert.ToChar(34));
                    Console.WriteLine("Decrypt Useage: encryptString decrypt -s {0}stringValue{0}", Convert.ToChar(34));
                    Console.WriteLine("\n");
                    break;
            }

            System.Environment.Exit(0);
        }

        // Function to encrypt the string for storage

        public static string EncryptString(string text, string keyString)
        {
            var key = Encoding.UTF8.GetBytes(keyString);
            using (var aesAlg = Aes.Create())
            {
                using (var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }
                        var iv = aesAlg.IV;
                        var decryptedContent = msEncrypt.ToArray();
                        var result = new byte[iv.Length + decryptedContent.Length];
                        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                        Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

                        return Convert.ToBase64String(result);
                    }
                }
            }
        }

        // Function decrypt the string for use

        public static string DecryptString(string cipherText, string keyString)
        {
            var fullCipher = Convert.FromBase64String(cipherText);
            var iv = new byte[16];
            var cipher = new byte[fullCipher.Length - iv.Length];
            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);
            var key = Encoding.UTF8.GetBytes(keyString);
            using (var aesAlg = Aes.Create())
            {
                using (var decryptor = aesAlg.CreateDecryptor(key, iv))
                {
                    string result;
                    using (var msDecrypt = new MemoryStream(cipher))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                    return result;
                }
            }
        }
    }
}
