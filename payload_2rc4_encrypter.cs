using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace Payload_Encrypt_Maker
{
    class Program
    {
        /// <summary>
        /// Harcoded KEY: 123123123123 in bytes
        /// </summary>
        static byte[] KEY = { 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33 };


        private static class Encryption_Class
        {
            public static string Encrypt(string key, string data)
            {
                Encoding unicode = Encoding.Unicode;
                return Convert.ToBase64String(Encrypt(unicode.GetBytes(key), unicode.GetBytes(data)));
            }

            public static string Decrypt(string key, string data)
            {
                Encoding unicode = Encoding.Unicode;
                return unicode.GetString(Encrypt(unicode.GetBytes(key), Convert.FromBase64String(data)));
            }

            public static byte[] Encrypt(byte[] key, byte[] data)
            {
                return EncryptOutput(key, data).ToArray();
            }

            public static byte[] Decrypt(byte[] key, byte[] data)
            {
                return EncryptOutput(key, data).ToArray();
            }

            private static byte[] EncryptInitalize(byte[] key)
            {
                byte[] s = Enumerable.Range(0, 256)
                  .Select(i => (byte)i)
                  .ToArray();

                for (int i = 0, j = 0; i < 256; i++)
                {
                    j = (j + key[i % key.Length] + s[i]) & 255;

                    Swap(s, i, j);
                }

                return s;
            }

            private static IEnumerable<byte> EncryptOutput(byte[] key, IEnumerable<byte> data)
            {
                byte[] s = EncryptInitalize(key);

                int i = 0;
                int j = 0;

                return data.Select((b) =>
                {
                    i = (i + 1) & 255;
                    j = (j + s[i]) & 255;

                    Swap(s, i, j);

                    return (byte)(b ^ s[(s[i] + s[j]) & 255]);
                });
            }

            private static void Swap(byte[] s, int i, int j)
            {
                byte c = s[i];

                s[i] = s[j];
                s[j] = c;
            }
        }
        static void Main(string[] args)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Payload Encryption tool.");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine();
            Console.WriteLine("[!] Using RC4 Encryption for your Payload");


            string[] InputArg = args[0].Split(',');
            byte[] XPay = new byte[InputArg.Length];

            Console.WriteLine("[!] Detecting Payload by Arguments");
            Console.Write("[!] Payload Length is: ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write(XPay.Length.ToString() + "\n");
            Console.ForegroundColor = ConsoleColor.DarkGreen;

            for (int i = 0; i < XPay.Length; i++)
            {
                XPay[i] = Convert.ToByte(InputArg[i], 16);
            }

            Console.WriteLine("[!] Loading Payload in Memory Done.");

            byte[] Xresult = Encryption_Class.Encrypt(KEY, XPay);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[>] Encrypting Payload in Memory by KEY Done.");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.Write("[!] Encryption KEY is:");
            Console.ForegroundColor = ConsoleColor.Yellow;

            string Keys = "";
            foreach (byte item in KEY)
            {
                Keys += item.ToString("x2") + " ";
            }

            Console.Write(" {0}", Convert.ToString(Keys));
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("[+] Encrypted Payload with Length {0} is: ", XPay.Length.ToString());
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine();

            for (int i = 0; i < Xresult.Length; i++)
            {
                Console.Write(" " + Xresult[i].ToString());
            }
            Console.WriteLine();
            Console.WriteLine();



        }
    }
}
