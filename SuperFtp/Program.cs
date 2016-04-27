namespace SuperFtp
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.FtpClient;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Text.RegularExpressions;

    internal class Program
    {
        private static BRE bre;
        private static System.Net.FtpClient.FtpClient client;
        private static List<string> commandParams = new List<string>();
        private static Dictionary<string, Action> Commands;
        private static bool hash;
        private static string localPath = Environment.CurrentDirectory;

        static Program()
        {
            Dictionary<string, Action> dictionary = new Dictionary<string, Action>();
            dictionary.Add("open", new Action(Program.Open));
            dictionary.Add("close", new Action(Program.Close));
            dictionary.Add("user", new Action(Program.User));
            dictionary.Add("use", new Action(Program.User));
            dictionary.Add("binary", new Action(Program.Binary));
            dictionary.Add("mkdir", () => Execute("MKD", true));
            dictionary.Add("rmdir", () => Execute("RMD", true));
            dictionary.Add("hash", delegate
            {
                hash = true;
                Console.WriteLine("hash opened.");
            });
            dictionary.Add("cd", () => Execute("CWD", true));
            dictionary.Add("lcd", new Action(Program.Lcd));
            dictionary.Add("clear", () => Console.Clear());
            dictionary.Add("mput", new Action(Program.Mput));
            dictionary.Add("rm", () => Execute("DELE", true));
            dictionary.Add("pwd", () => Execute("PWD", false));
            dictionary.Add("ls", delegate
            {
                if (CheckClient())
                    foreach (FtpListItem item in client.GetListing())
                    {
                        Console.WriteLine(item.Name);
                    }
            });
            Commands = dictionary;
        }

        private static void Copy(string src, string target)
        {
            var targetUrl = new Uri(target);

            ParameterParse(targetUrl.Host + " " + targetUrl.Port);
            Open();

            ParameterParse(targetUrl.UserInfo.Replace(":", " "));
            User();

            ParameterParse(targetUrl.AbsolutePath);
            Execute("CWD", true);

            ParameterParse(src);
            Mput();

        }

        private static void Binary()
        {
            if ((client == null) || !client.IsConnected)
            {
                Console.WriteLine("not connected.");
            }
            else
            {
                FtpReply reply = client.Execute("TYPE I");
                Console.WriteLine(reply.Code + " " + reply.Message);
            }
        }

        private static bool CheckClient()
        {
            if ((client != null) && client.IsConnected)
            {
                return true;
            }
            Console.WriteLine("not connected.");
            return false;
        }

        private static void client_ValidateCertificate(System.Net.FtpClient.FtpClient control, FtpSslValidationEventArgs e)
        {
            if (e.Accept)
            {
                Console.WriteLine("certificate accept.");
            }
            else
            {
                Console.WriteLine("error:" + e.PolicyErrors.ToString());
            }
            throw new NotImplementedException();
        }

        private static void Close()
        {
            if (client != null)
            {
                client.Disconnect();
            }
        }

        private static void Execute(string command, bool appendParams = false)
        {
            if (CheckClient() && (!appendParams || HasParam("parameter invalidate.")))
            {
                if (appendParams)
                {
                    command = command + " " + commandParams.Aggregate<string>((s, s1) => (s + " " + s1));
                }
                FtpReply reply = client.Execute(command);
                Console.WriteLine(reply.Code + " " + reply.Message);
            }
        }

        private static bool HasParam(string msg = "parameter invalidate.")
        {
            if (commandParams.Count == 0)
            {
                Console.WriteLine(msg);
                return false;
            }
            return true;
        }

        private static void Lcd()
        {
            if (HasParam("parameter invalidate."))
            {
                string fullPath = Path.GetFullPath(Path.Combine(localPath, commandParam));
                if (Directory.Exists(fullPath))
                {
                    localPath = fullPath;
                }
                else
                {
                    Console.WriteLine("directory don't exists.");
                }
            }
        }

        private static void Main(string[] args)
        {
            if (args != null && args.Length > 2 && args[0] == "copy")
            {
                Copy(args[1], args[2]);
                return;
            }
            string str = Commands.Keys.Aggregate<string>((c, c1) => c + "|" + c1);
            Regex regex = new Regex(@"^\s{0,}(" + str + @")\s{0,}");
            string str2 = string.Empty;
            while (true)
            {
                Console.Write("ftp> ");
                str2 = Console.ReadLine();
                if (((str2 == "bye") || ((str2 == "exit") | (str2 == "q"))) || (str2 == null))
                {
                    return;
                }
                if (!string.IsNullOrWhiteSpace(str2))
                {
                    Match match = regex.Match(str2);
                    if (match.Success)
                    {
                        ParameterParse(regex.Replace(str2, ""));
                        try
                        {
                            Commands[match.Groups[1].Value]();
                        }
                        catch (SocketException exception)
                        {
                            Console.WriteLine(exception.Message);
                        }
                    }
                    else
                    {
                        Console.WriteLine("command not found.");
                    }
                }
            }
        }

        private static void Mput()
        {
            if (CheckClient() && HasParam("parameter invalidate."))
            {
                bre = new BRE(commandParam);
                UploadDirectory(localPath, true);
            }
        }

        private static void Open()
        {
            Close();
            if (commandParams.Count == 0)
            {
                Console.WriteLine("Usage:open host [port]");
            }
            else
            {
                string str = commandParams[0];
                int result = 0;
                if (commandParams.Count == 1)
                {
                    commandParams.Add("21");
                }
                if (!int.TryParse(commandParams[1], out result))
                {
                    Console.WriteLine("unknow port!");
                }
                else
                {
                    client = new System.Net.FtpClient.FtpClient();
                    client.Host = str;
                    client.Port = result;
                    client.DataConnectionType = FtpDataConnectionType.PASV;
                    client.Connect();
                    client.ValidateCertificate += new FtpSslValidation(Program.client_ValidateCertificate);
                }
            }
        }

        private static List<string> ParameterParse(string line)
        {
            commandParams.Clear();
            foreach (string str in line.Split(new char[] { ' ' }))
            {
                if (!string.IsNullOrEmpty(str))
                {
                    commandParams.Add(str);
                }
            }
            return commandParams;
        }

        private static void UploadDirectory(string path, bool breUse = false)
        {
            IEnumerable<string> enumerable = Directory.GetFiles(path).Where<string>(delegate(string file)
            {
                if (breUse)
                {
                    return bre.IsMatch(Path.GetFileName(file));
                }
                return true;
            });
            IEnumerable<string> enumerable2 = Directory.GetDirectories(path).Where<string>(delegate(string directory)
            {
                if (breUse)
                {
                    return bre.IsMatch(Path.GetFileName(directory));
                }
                return true;
            });
            foreach (string str in enumerable)
            {
                UploadFile(str);
            }
            foreach (string str2 in enumerable2)
            {
                string fileName = Path.GetFileName(str2);
                if (!client.DirectoryExists(fileName))
                {
                    client.CreateDirectory(fileName);
                }
                Execute("CWD " + fileName, false);
                UploadDirectory(Path.Combine(path, fileName), false);
                Execute("CWD ..", false);
            }
        }

        private static void UploadFile(string file)
        {
            string fileName = Path.GetFileName(file);
            using (Stream stream = client.OpenWrite(fileName))
            {
                Console.Write(fileName + "\t\t");
                byte[] buffer = System.IO.File.ReadAllBytes(file);
                int num = 0;
                for (int i = 0x400; i < buffer.Length; i += 0x400)
                {
                    int count = i - num;
                    count = ((count + i) > buffer.Length) ? (buffer.Length - i) : count;
                    stream.Write(buffer, i, count);

                    try
                    {
                        Console.SetCursorPosition(fileName.Length + 12, Console.CursorTop);
                        Console.Write(Math.Ceiling((decimal)((i / buffer.Length) * 100M)) + "%");
                    }
                    catch (Exception)
                    {
                    }
                    num = i;
                }
                try
                {
                    Console.SetCursorPosition(fileName.Length + 12, Console.CursorTop);
                }
                catch (Exception)
                {
                }
                Console.WriteLine("100%");
            }
        }

        private static void User()
        {
            if ((client == null) || !client.IsConnected)
            {
                Console.WriteLine("not connected.");
            }
            else if (commandParams.Count == 0)
            {
                Console.WriteLine("Usage:user naem [password]");
            }
            else
            {
                client.Credentials = new NetworkCredential(commandParams[0], (commandParams.Count == 1) ? "" : commandParams[1]);
                FtpReply reply = client.Execute("User " + commandParams[0]);
                if ((commandParams.Count == 1) && !reply.Success)
                {
                    Console.WriteLine(reply.Code + " " + reply.Message);
                }
                if (commandParams.Count > 1)
                {
                    reply = client.Execute("PASS " + commandParams[1]);
                }
                Console.WriteLine(reply.Code + " " + reply.Message);
            }
        }

        private static string commandParam
        {
            get
            {
                if (commandParams.Count != 0)
                {
                    return commandParams[0];
                }
                return null;
            }
        }
    }
}

