namespace System.Net.FtpClient
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Reflection;
    using System.Runtime.CompilerServices;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Web;

    public class FtpClient : IFtpClient, IDisposable
    {
        private readonly Dictionary<IAsyncResult, object> m_asyncmethods = new Dictionary<IAsyncResult, object>();
        private FtpCapability m_caps;
        private X509CertificateCollection m_clientCerts = new X509CertificateCollection();
        private int m_connectTimeout = 0x3a98;
        private NetworkCredential m_credentials;
        private int m_dataConnectionConnectTimeout = 0x3a98;
        private bool m_dataConnectionEncryption = true;
        private int m_dataConnectionReadTimeout = 0x3a98;
        private FtpDataConnectionType m_dataConnectionType;
        private FtpEncryptionMode m_encryptionmode;
        private FtpHashAlgorithm m_hashAlgorithms;
        private string m_host;
        private FtpIpVersion m_ipVersions = FtpIpVersion.ANY;
        private bool m_isClone;
        private bool m_isDisposed;
        private bool m_keepAlive;
        private readonly object m_lock = new object();
        private int m_maxDerefCount = 20;
        private int m_port;
        private int m_readTimeout = 0x3a98;
        private int m_socketPollInterval = 0x3a98;
        private System.Security.Authentication.SslProtocols m_SslProtocols = System.Security.Authentication.SslProtocols.Default;
        private bool m_staleDataTest = true;
        private FtpSocketStream m_stream;
        private System.Text.Encoding m_textEncoding = System.Text.Encoding.ASCII;
        private bool m_threadSafeDataChannels = true;
        private bool m_ungracefullDisconnect;

        public event FtpSslValidation ValidateCertificate;

        protected virtual void Authenticate()
        {
            FtpReply reply;
            FtpReply reply2 = reply = this.Execute("USER {0}", new object[] { this.Credentials.UserName });
            if (!reply2.Success)
            {
                throw new FtpCommandException(reply);
            }
            if (reply.Type == FtpResponseType.PositiveIntermediate)
            {
                FtpReply reply3 = reply = this.Execute("PASS {0}", new object[] { this.Credentials.Password });
                if (!reply3.Success)
                {
                    throw new FtpCommandException(reply);
                }
            }
        }

        public IAsyncResult BeginConnect(AsyncCallback callback, object state)
        {
            AsyncConnect connect;
            IAsyncResult key = (connect = new AsyncConnect(this.Connect)).BeginInvoke(callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, connect);
            }
            return key;
        }

        public IAsyncResult BeginCreateDirectory(string path, AsyncCallback callback, object state)
        {
            return this.BeginCreateDirectory(path, true, callback, state);
        }

        public IAsyncResult BeginCreateDirectory(string path, bool force, AsyncCallback callback, object state)
        {
            AsyncCreateDirectory directory;
            IAsyncResult key = (directory = new AsyncCreateDirectory(this.CreateDirectory)).BeginInvoke(path, force, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, directory);
            }
            return key;
        }

        public IAsyncResult BeginDeleteDirectory(string path, AsyncCallback callback, object state)
        {
            return this.BeginDeleteDirectory(path, true, 0, callback, state);
        }

        public IAsyncResult BeginDeleteDirectory(string path, bool force, AsyncCallback callback, object state)
        {
            return this.BeginDeleteDirectory(path, force, 0, callback, state);
        }

        public IAsyncResult BeginDeleteDirectory(string path, bool force, FtpListOption options, AsyncCallback callback, object state)
        {
            AsyncDeleteDirectory directory;
            IAsyncResult key = (directory = new AsyncDeleteDirectory(this.DeleteDirectory)).BeginInvoke(path, force, options, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, directory);
            }
            return key;
        }

        public IAsyncResult BeginDeleteFile(string path, AsyncCallback callback, object state)
        {
            AsyncDeleteFile file;
            IAsyncResult key = (file = new AsyncDeleteFile(this.DeleteFile)).BeginInvoke(path, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, file);
            }
            return key;
        }

        public IAsyncResult BeginDereferenceLink(FtpListItem item, AsyncCallback callback, object state)
        {
            return this.BeginDereferenceLink(item, this.MaximumDereferenceCount, callback, state);
        }

        public IAsyncResult BeginDereferenceLink(FtpListItem item, int recMax, AsyncCallback callback, object state)
        {
            AsyncDereferenceLink link;
            IAsyncResult key = (link = new AsyncDereferenceLink(this.DereferenceLink)).BeginInvoke(item, recMax, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, link);
            }
            return key;
        }

        public IAsyncResult BeginDirectoryExists(string path, AsyncCallback callback, object state)
        {
            AsyncDirectoryExists exists;
            IAsyncResult key = (exists = new AsyncDirectoryExists(this.DirectoryExists)).BeginInvoke(path, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, exists);
            }
            return key;
        }

        public IAsyncResult BeginDisconnect(AsyncCallback callback, object state)
        {
            AsyncDisconnect disconnect;
            IAsyncResult key = (disconnect = new AsyncDisconnect(this.Disconnect)).BeginInvoke(callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, disconnect);
            }
            return key;
        }

        public IAsyncResult BeginExecute(string command, AsyncCallback callback, object state)
        {
            AsyncExecute execute;
            IAsyncResult key = (execute = new AsyncExecute(this.Execute)).BeginInvoke(command, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, execute);
            }
            return key;
        }

        public IAsyncResult BeginFileExists(string path, AsyncCallback callback, object state)
        {
            return this.BeginFileExists(path, 0, callback, state);
        }

        public IAsyncResult BeginFileExists(string path, FtpListOption options, AsyncCallback callback, object state)
        {
            AsyncFileExists exists;
            IAsyncResult key = (exists = new AsyncFileExists(this.FileExists)).BeginInvoke(path, options, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, exists);
            }
            return key;
        }

        public IAsyncResult BeginGetFileSize(string path, AsyncCallback callback, object state)
        {
            AsyncGetFileSize size;
            IAsyncResult key = (size = new AsyncGetFileSize(this.GetFileSize)).BeginInvoke(path, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, size);
            }
            return key;
        }

        public IAsyncResult BeginGetHash(string path, AsyncCallback callback, object state)
        {
            AsyncGetHash hash;
            IAsyncResult key = (hash = new AsyncGetHash(this.GetHash)).BeginInvoke(path, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, hash);
            }
            return key;
        }

        public IAsyncResult BeginGetHashAlgorithm(AsyncCallback callback, object state)
        {
            AsyncGetHashAlgorithm algorithm;
            IAsyncResult key = (algorithm = new AsyncGetHashAlgorithm(this.GetHashAlgorithm)).BeginInvoke(callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, algorithm);
            }
            return key;
        }

        public IAsyncResult BeginGetListing(AsyncCallback callback, object state)
        {
            return this.BeginGetListing(null, callback, state);
        }

        public IAsyncResult BeginGetListing(string path, AsyncCallback callback, object state)
        {
            return this.BeginGetListing(path, FtpListOption.SizeModify, callback, state);
        }

        public IAsyncResult BeginGetListing(string path, FtpListOption options, AsyncCallback callback, object state)
        {
            AsyncGetListing listing;
            IAsyncResult key = (listing = new AsyncGetListing(this.GetListing)).BeginInvoke(path, options, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, listing);
            }
            return key;
        }

        public IAsyncResult BeginGetModifiedTime(string path, AsyncCallback callback, object state)
        {
            AsyncGetModifiedTime time;
            IAsyncResult key = (time = new AsyncGetModifiedTime(this.GetModifiedTime)).BeginInvoke(path, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, time);
            }
            return key;
        }

        public IAsyncResult BeginGetNameListing(AsyncCallback callback, object state)
        {
            return this.BeginGetNameListing(null, callback, state);
        }

        public IAsyncResult BeginGetNameListing(string path, AsyncCallback callback, object state)
        {
            AsyncGetNameListing listing;
            IAsyncResult key = (listing = new AsyncGetNameListing(this.GetNameListing)).BeginInvoke(path, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, listing);
            }
            return key;
        }

        public IAsyncResult BeginGetObjectInfo(string path, AsyncCallback callback, object state)
        {
            AsyncGetObjectInfo info;
            IAsyncResult key = (info = new AsyncGetObjectInfo(this.GetObjectInfo)).BeginInvoke(path, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, info);
            }
            return key;
        }

        public IAsyncResult BeginGetWorkingDirectory(AsyncCallback callback, object state)
        {
            AsyncGetWorkingDirectory directory;
            IAsyncResult key = (directory = new AsyncGetWorkingDirectory(this.GetWorkingDirectory)).BeginInvoke(callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, directory);
            }
            return key;
        }

        public IAsyncResult BeginOpenAppend(string path, AsyncCallback callback, object state)
        {
            return this.BeginOpenAppend(path, FtpDataType.Binary, callback, state);
        }

        public IAsyncResult BeginOpenAppend(string path, FtpDataType type, AsyncCallback callback, object state)
        {
            AsyncOpenAppend append;
            IAsyncResult key = (append = new AsyncOpenAppend(this.OpenAppend)).BeginInvoke(path, type, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, append);
            }
            return key;
        }

        public IAsyncResult BeginOpenRead(string path, AsyncCallback callback, object state)
        {
            return this.BeginOpenRead(path, FtpDataType.Binary, 0L, callback, state);
        }

        public IAsyncResult BeginOpenRead(string path, long restart, AsyncCallback callback, object state)
        {
            return this.BeginOpenRead(path, FtpDataType.Binary, restart, callback, state);
        }

        public IAsyncResult BeginOpenRead(string path, FtpDataType type, AsyncCallback callback, object state)
        {
            return this.BeginOpenRead(path, type, 0L, callback, state);
        }

        public IAsyncResult BeginOpenRead(string path, FtpDataType type, long restart, AsyncCallback callback, object state)
        {
            AsyncOpenRead read;
            IAsyncResult key = (read = new AsyncOpenRead(this.OpenRead)).BeginInvoke(path, type, restart, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, read);
            }
            return key;
        }

        public IAsyncResult BeginOpenWrite(string path, AsyncCallback callback, object state)
        {
            return this.BeginOpenWrite(path, FtpDataType.Binary, callback, state);
        }

        public IAsyncResult BeginOpenWrite(string path, FtpDataType type, AsyncCallback callback, object state)
        {
            AsyncOpenWrite write;
            IAsyncResult key = (write = new AsyncOpenWrite(this.OpenWrite)).BeginInvoke(path, type, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, write);
            }
            return key;
        }

        public IAsyncResult BeginRename(string path, string dest, AsyncCallback callback, object state)
        {
            AsyncRename rename;
            IAsyncResult key = (rename = new AsyncRename(this.Rename)).BeginInvoke(path, dest, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, rename);
            }
            return key;
        }

        protected IAsyncResult BeginSetDataType(FtpDataType type, AsyncCallback callback, object state)
        {
            AsyncSetDataType type2;
            IAsyncResult key = (type2 = new AsyncSetDataType(this.SetDataType)).BeginInvoke(type, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, type2);
            }
            return key;
        }

        public IAsyncResult BeginSetHashAlgorithm(FtpHashAlgorithm type, AsyncCallback callback, object state)
        {
            AsyncSetHashAlgorithm algorithm;
            IAsyncResult key = (algorithm = new AsyncSetHashAlgorithm(this.SetHashAlgorithm)).BeginInvoke(type, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, algorithm);
            }
            return key;
        }

        public IAsyncResult BeginSetWorkingDirectory(string path, AsyncCallback callback, object state)
        {
            AsyncSetWorkingDirectory directory;
            IAsyncResult key = (directory = new AsyncSetWorkingDirectory(this.SetWorkingDirectory)).BeginInvoke(path, callback, state);
            lock (this.m_asyncmethods)
            {
                this.m_asyncmethods.Add(key, directory);
            }
            return key;
        }

        protected System.Net.FtpClient.FtpClient CloneConnection()
        {
            System.Net.FtpClient.FtpClient client = new System.Net.FtpClient.FtpClient {
                m_isClone = true
            };
            foreach (PropertyInfo info in base.GetType().GetProperties())
            {
                object[] customAttributes = info.GetCustomAttributes(typeof(FtpControlConnectionClone), true);
                if ((customAttributes != null) && (customAttributes.Length > 0))
                {
                    info.SetValue(client, info.GetValue(this, null), null);
                }
            }
            client.ValidateCertificate += delegate (System.Net.FtpClient.FtpClient obj, FtpSslValidationEventArgs e) {
                e.Accept = true;
            };
            return client;
        }

        internal FtpReply CloseDataStream(System.Net.FtpClient.FtpDataStream stream)
        {
            FtpReply reply = new FtpReply();
            if (stream == null)
            {
                throw new ArgumentException("The data stream parameter was null");
            }
            lock (this.m_lock)
            {
                try
                {
                    if (this.IsConnected && (stream.CommandStatus.Type == FtpResponseType.PositivePreliminary))
                    {
                        FtpReply reply3 = reply = this.GetReply();
                        if (!reply3.Success)
                        {
                            throw new FtpCommandException(reply);
                        }
                    }
                }
                finally
                {
                    if (this.IsClone)
                    {
                        this.Disconnect();
                        this.Dispose();
                    }
                }
            }
            return reply;
        }

        public virtual void Connect()
        {
            lock (this.m_lock)
            {
                FtpReply reply;
                if (this.IsDisposed)
                {
                    throw new ObjectDisposedException("This FtpClient object has been disposed. It is no longer accessible.");
                }
                if (this.m_stream == null)
                {
                    this.m_stream = new FtpSocketStream();
                    this.m_stream.ValidateCertificate += new FtpSocketStreamSslValidation(this.FireValidateCertficate);
                }
                else if (this.IsConnected)
                {
                    this.Disconnect();
                }
                if (this.Host == null)
                {
                    throw new FtpException("No host has been specified");
                }
                if (!this.IsClone)
                {
                    this.m_caps = FtpCapability.NONE;
                }
                this.m_hashAlgorithms = FtpHashAlgorithm.NONE;
                this.m_stream.ConnectTimeout = this.m_connectTimeout;
                this.m_stream.SocketPollInterval = this.m_socketPollInterval;
                this.m_stream.Connect(this.Host, this.Port, this.InternetProtocolVersions);
                this.m_stream.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, this.m_keepAlive);
                if (this.EncryptionMode == FtpEncryptionMode.Implicit)
                {
                    this.m_stream.ActivateEncryption(this.Host, (this.m_clientCerts.Count > 0) ? this.m_clientCerts : null, this.m_SslProtocols);
                }
                FtpReply reply2 = reply = this.GetReply();
                if (!reply2.Success)
                {
                    if (reply.Code == null)
                    {
                        throw new IOException("The connection was terminated before a greeting could be read.");
                    }
                    throw new FtpCommandException(reply);
                }
                if (this.EncryptionMode == FtpEncryptionMode.Explicit)
                {
                    FtpReply reply3 = reply = this.Execute("AUTH TLS");
                    if (!reply3.Success)
                    {
                        throw new FtpSecurityNotAvailableException("AUTH TLS command failed.");
                    }
                    this.m_stream.ActivateEncryption(this.Host, (this.m_clientCerts.Count > 0) ? this.m_clientCerts : null, this.m_SslProtocols);
                }
                if (this.m_credentials != null)
                {
                    this.Authenticate();
                }
                if (this.m_stream.IsEncrypted && this.DataConnectionEncryption)
                {
                    FtpReply reply4 = reply = this.Execute("PBSZ 0");
                    if (!reply4.Success)
                    {
                        throw new FtpCommandException(reply);
                    }
                    FtpReply reply5 = reply = this.Execute("PROT P");
                    if (!reply5.Success)
                    {
                        throw new FtpCommandException(reply);
                    }
                }
                if (!this.IsClone)
                {
                    FtpReply reply6 = reply = this.Execute("FEAT");
                    if (reply6.Success && (reply.InfoMessages != null))
                    {
                        this.GetFeatures(reply);
                    }
                }
                if ((this.m_textEncoding == System.Text.Encoding.ASCII) && this.HasFeature(FtpCapability.UTF8))
                {
                    this.m_textEncoding = System.Text.Encoding.UTF8;
                }
                FtpTrace.WriteLine("Text encoding: " + this.m_textEncoding.ToString());
                if (this.m_textEncoding == System.Text.Encoding.UTF8)
                {
                    this.Execute("OPTS UTF8 ON");
                }
            }
        }

        public static System.Net.FtpClient.FtpClient Connect(Uri uri)
        {
            return Connect(uri, true);
        }

        public static System.Net.FtpClient.FtpClient Connect(Uri uri, bool checkcertificate)
        {
            string str;
            System.Net.FtpClient.FtpClient client = new System.Net.FtpClient.FtpClient();
            if (uri == null)
            {
                throw new ArgumentException("Invalid URI object");
            }
            if (((str = uri.Scheme.ToLower()) == null) || ((str != "ftp") && (str != "ftps")))
            {
                throw new UriFormatException("The specified URI scheme is not supported. Please use ftp:// or ftps://");
            }
            client.Host = uri.Host;
            client.Port = uri.Port;
            if ((uri.UserInfo != null) && (uri.UserInfo.Length > 0))
            {
                if (uri.UserInfo.Contains(":"))
                {
                    string[] strArray = uri.UserInfo.Split(new char[] { ':' });
                    if (strArray.Length != 2)
                    {
                        throw new UriFormatException("The user info portion of the URI contains more than 1 colon. The username and password portion of the URI should be URL encoded.");
                    }
                    client.Credentials = new NetworkCredential(HttpUtility.UrlDecode(strArray[0]), HttpUtility.UrlDecode(strArray[1]));
                }
                else
                {
                    client.Credentials = new NetworkCredential(HttpUtility.UrlDecode(uri.UserInfo), "");
                }
            }
            else
            {
                client.Credentials = new NetworkCredential("ftp", "ftp");
            }
            client.ValidateCertificate += delegate (System.Net.FtpClient.FtpClient control, FtpSslValidationEventArgs e) {
                if ((e.PolicyErrors != SslPolicyErrors.None) && checkcertificate)
                {
                    e.Accept = false;
                }
                else
                {
                    e.Accept = true;
                }
            };
            client.Connect();
            if ((uri.PathAndQuery != null) && uri.PathAndQuery.EndsWith("/"))
            {
                client.SetWorkingDirectory(uri.PathAndQuery);
            }
            return client;
        }

        public void CreateDirectory(string path)
        {
            this.CreateDirectory(path, true);
        }

        public void CreateDirectory(string path, bool force)
        {
            string ftpPath = path.GetFtpPath();
            switch (ftpPath)
            {
                case ".":
                case "./":
                case "/":
                    return;
            }
            lock (this.m_lock)
            {
                FtpReply reply;
                path = path.GetFtpPath().TrimEnd(new char[] { '/' });
                if (force && !this.DirectoryExists(path.GetFtpDirectoryName()))
                {
                    FtpTrace.WriteLine(string.Format("CreateDirectory(\"{0}\", {1}): Create non-existent parent: {2}", path, force, path.GetFtpDirectoryName()));
                    this.CreateDirectory(path.GetFtpDirectoryName(), true);
                }
                else if (this.DirectoryExists(path))
                {
                    goto Label_00F4;
                }
                FtpTrace.WriteLine(string.Format("CreateDirectory(\"{0}\", {1})", ftpPath, force));
                FtpReply reply2 = reply = this.Execute("MKD {0}", new object[] { ftpPath });
                if (!reply2.Success)
                {
                    throw new FtpCommandException(reply);
                }
            Label_00F4:;
            }
        }

        public void DeleteDirectory(string path)
        {
            this.DeleteDirectory(path, false);
        }

        public void DeleteDirectory(string path, bool force)
        {
            this.DeleteDirectory(path, force, 0);
        }

        public void DeleteDirectory(string path, bool force, FtpListOption options)
        {
            string ftpPath = path.GetFtpPath();
            lock (this.m_lock)
            {
                if (force)
                {
                    foreach (FtpListItem item in this.GetListing(path, options))
                    {
                        switch (item.Type)
                        {
                            case FtpFileSystemObjectType.File:
                                this.DeleteFile(item.FullName);
                                break;

                            case FtpFileSystemObjectType.Directory:
                                this.DeleteDirectory(item.FullName, true, options);
                                break;

                            default:
                                throw new FtpException("Don't know how to delete object type: " + item.Type);
                        }
                    }
                }
                switch (ftpPath)
                {
                    case ".":
                    case "./":
                    case "/":
                        break;

                    default:
                    {
                        FtpReply reply;
                        FtpReply reply2 = reply = this.Execute("RMD {0}", new object[] { ftpPath });
                        if (!reply2.Success)
                        {
                            throw new FtpCommandException(reply);
                        }
                        break;
                    }
                }
            }
        }

        public void DeleteFile(string path)
        {
            lock (this.m_lock)
            {
                FtpReply reply;
                FtpReply reply2 = reply = this.Execute("DELE {0}", new object[] { path.GetFtpPath() });
                if (!reply2.Success)
                {
                    throw new FtpCommandException(reply);
                }
            }
        }

        public FtpListItem DereferenceLink(FtpListItem item)
        {
            return this.DereferenceLink(item, this.MaximumDereferenceCount);
        }

        public FtpListItem DereferenceLink(FtpListItem item, int recMax)
        {
            int count = 0;
            return this.DereferenceLink(item, recMax, ref count);
        }

        private FtpListItem DereferenceLink(FtpListItem item, int recMax, ref int count)
        {
            if (item.Type != FtpFileSystemObjectType.Link)
            {
                throw new FtpException("You can only derefernce a symbolic link. Please verify the item type is Link.");
            }
            if (item.LinkTarget == null)
            {
                throw new FtpException("The link target was null. Please check this before trying to dereference the link.");
            }
            foreach (FtpListItem item2 in this.GetListing(item.LinkTarget.GetFtpDirectoryName(), FtpListOption.ForceList))
            {
                if (item.LinkTarget == item2.FullName)
                {
                    if (item2.Type == FtpFileSystemObjectType.Link)
                    {
                        if (++count == recMax)
                        {
                            return null;
                        }
                        return this.DereferenceLink(item2, recMax, ref count);
                    }
                    if (this.HasFeature(FtpCapability.MDTM))
                    {
                        DateTime modifiedTime = this.GetModifiedTime(item2.FullName);
                        if (modifiedTime != DateTime.MinValue)
                        {
                            item2.Modified = modifiedTime;
                        }
                    }
                    if (((item2.Type == FtpFileSystemObjectType.File) && (item2.Size < 0L)) && this.HasFeature(FtpCapability.SIZE))
                    {
                        item2.Size = this.GetFileSize(item2.FullName);
                    }
                    return item2;
                }
            }
            return null;
        }

        public bool DirectoryExists(string path)
        {
            string ftpPath = path.GetFtpPath();
            switch (ftpPath)
            {
                case ".":
                case "./":
                case "/":
                    return true;
            }
            lock (this.m_lock)
            {
                string workingDirectory = this.GetWorkingDirectory();
                if (this.Execute("CWD {0}", new object[] { ftpPath }).Success)
                {
                    if (!this.Execute("CWD {0}", new object[] { workingDirectory.GetFtpPath() }).Success)
                    {
                        throw new FtpException("DirectoryExists(): Failed to restore the working directory.");
                    }
                    return true;
                }
            }
            return false;
        }

        public void DisableUTF8()
        {
            lock (this.m_lock)
            {
                FtpReply reply;
                FtpReply reply2 = reply = this.Execute("OPTS UTF8 OFF");
                if (!reply2.Success)
                {
                    throw new FtpCommandException(reply);
                }
                this.m_textEncoding = System.Text.Encoding.ASCII;
            }
        }

        public virtual void Disconnect()
        {
            lock (this.m_lock)
            {
                if ((this.m_stream != null) && this.m_stream.IsConnected)
                {
                    try
                    {
                        if (!this.UngracefullDisconnection)
                        {
                            this.Execute("QUIT");
                        }
                    }
                    catch (SocketException exception)
                    {
                        FtpTrace.WriteLine("FtpClient.Disconnect(): SocketException caught and discarded while closing control connection: {0}", new object[] { exception.ToString() });
                    }
                    catch (IOException exception2)
                    {
                        FtpTrace.WriteLine("FtpClient.Disconnect(): IOException caught and discarded while closing control connection: {0}", new object[] { exception2.ToString() });
                    }
                    catch (FtpCommandException exception3)
                    {
                        FtpTrace.WriteLine("FtpClient.Disconnect(): FtpCommandException caught and discarded while closing control connection: {0}", new object[] { exception3.ToString() });
                    }
                    catch (FtpException exception4)
                    {
                        FtpTrace.WriteLine("FtpClient.Disconnect(): FtpException caught and discarded while closing control connection: {0}", new object[] { exception4.ToString() });
                    }
                    finally
                    {
                        this.m_stream.Close();
                    }
                }
            }
        }

        public void Dispose()
        {
            lock (this.m_lock)
            {
                if (!this.IsDisposed)
                {
                    FtpTrace.WriteLine("Disposing FtpClient object...");
                    try
                    {
                        if (this.IsConnected)
                        {
                            this.Disconnect();
                        }
                    }
                    catch (Exception exception)
                    {
                        FtpTrace.WriteLine("FtpClient.Dispose(): Caught and discarded an exception while disconnecting from host: {0}", new object[] { exception.ToString() });
                    }
                    if (this.m_stream != null)
                    {
                        try
                        {
                            this.m_stream.Dispose();
                        }
                        catch (Exception exception2)
                        {
                            FtpTrace.WriteLine("FtpClient.Dispose(): Caught and discarded an exception while disposing FtpStream object: {0}", new object[] { exception2.ToString() });
                        }
                        finally
                        {
                            this.m_stream = null;
                        }
                    }
                    this.m_credentials = null;
                    this.m_textEncoding = null;
                    this.m_host = null;
                    this.m_asyncmethods.Clear();
                    this.IsDisposed = true;
                    GC.SuppressFinalize(this);
                }
            }
        }

        public void EndConnect(IAsyncResult ar)
        {
            this.GetAsyncDelegate<AsyncConnect>(ar).EndInvoke(ar);
        }

        public void EndCreateDirectory(IAsyncResult ar)
        {
            this.GetAsyncDelegate<AsyncCreateDirectory>(ar).EndInvoke(ar);
        }

        public void EndDeleteDirectory(IAsyncResult ar)
        {
            this.GetAsyncDelegate<AsyncDeleteDirectory>(ar).EndInvoke(ar);
        }

        public void EndDeleteFile(IAsyncResult ar)
        {
            this.GetAsyncDelegate<AsyncDeleteFile>(ar).EndInvoke(ar);
        }

        public FtpListItem EndDereferenceLink(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncDereferenceLink>(ar).EndInvoke(ar);
        }

        public bool EndDirectoryExists(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncDirectoryExists>(ar).EndInvoke(ar);
        }

        public void EndDisconnect(IAsyncResult ar)
        {
            this.GetAsyncDelegate<AsyncDisconnect>(ar).EndInvoke(ar);
        }

        public FtpReply EndExecute(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncExecute>(ar).EndInvoke(ar);
        }

        public bool EndFileExists(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncFileExists>(ar).EndInvoke(ar);
        }

        public long EndGetFileSize(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncGetFileSize>(ar).EndInvoke(ar);
        }

        public void EndGetHash(IAsyncResult ar)
        {
            this.GetAsyncDelegate<AsyncGetHash>(ar).EndInvoke(ar);
        }

        public FtpHashAlgorithm EndGetHashAlgorithm(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncGetHashAlgorithm>(ar).EndInvoke(ar);
        }

        public FtpListItem[] EndGetListing(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncGetListing>(ar).EndInvoke(ar);
        }

        public DateTime EndGetModifiedTime(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncGetModifiedTime>(ar).EndInvoke(ar);
        }

        public string[] EndGetNameListing(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncGetNameListing>(ar).EndInvoke(ar);
        }

        public FtpListItem EndGetObjectInfo(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncGetObjectInfo>(ar).EndInvoke(ar);
        }

        public string EndGetWorkingDirectory(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncGetWorkingDirectory>(ar).EndInvoke(ar);
        }

        public Stream EndOpenAppend(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncOpenAppend>(ar).EndInvoke(ar);
        }

        public Stream EndOpenRead(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncOpenRead>(ar).EndInvoke(ar);
        }

        public Stream EndOpenWrite(IAsyncResult ar)
        {
            return this.GetAsyncDelegate<AsyncOpenWrite>(ar).EndInvoke(ar);
        }

        public void EndRename(IAsyncResult ar)
        {
            this.GetAsyncDelegate<AsyncRename>(ar).EndInvoke(ar);
        }

        protected void EndSetDataType(IAsyncResult ar)
        {
            this.GetAsyncDelegate<AsyncSetDataType>(ar).EndInvoke(ar);
        }

        public void EndSetHashAlgorithm(IAsyncResult ar)
        {
            this.GetAsyncDelegate<AsyncSetHashAlgorithm>(ar).EndInvoke(ar);
        }

        public void EndSetWorkingDirectory(IAsyncResult ar)
        {
            this.GetAsyncDelegate<AsyncSetWorkingDirectory>(ar).EndInvoke(ar);
        }

        public FtpReply Execute(string command)
        {
            lock (this.m_lock)
            {
                if ((this.StaleDataCheck && (this.m_stream != null)) && (this.m_stream.SocketDataAvailable > 0))
                {
                    FtpTrace.WriteLine("There is stale data on the socket, maybe our connection timed out. Re-connecting.");
                    if (this.m_stream.IsConnected && !this.m_stream.IsEncrypted)
                    {
                        byte[] buffer = new byte[this.m_stream.SocketDataAvailable];
                        this.m_stream.RawSocketRead(buffer);
                        FtpTrace.Write("The data was: ");
                        FtpTrace.WriteLine(this.Encoding.GetString(buffer).TrimEnd(new char[] { '\r', '\n' }));
                    }
                    this.m_stream.Close();
                }
                if (!this.IsConnected)
                {
                    if (command == "QUIT")
                    {
                        FtpTrace.WriteLine("Not sending QUIT because the connection has already been closed.");
                        return new FtpReply { Code = "200", Message = "Connection already closed." };
                    }
                    this.Connect();
                }
                FtpTrace.WriteLine(command.StartsWith("PASS") ? "PASS <omitted>" : command);
                this.m_stream.WriteLine(this.m_textEncoding, command);
                return this.GetReply();
            }
        }

        public FtpReply Execute(string command, params object[] args)
        {
            return this.Execute(string.Format(command, args));
        }

        public bool FileExists(string path)
        {
            return this.FileExists(path, 0);
        }

        public bool FileExists(string path, FtpListOption options)
        {
            string ftpDirectoryName = path.GetFtpDirectoryName();
            lock (this.m_lock)
            {
                if (!this.DirectoryExists(ftpDirectoryName))
                {
                    return false;
                }
                foreach (FtpListItem item in this.GetListing(ftpDirectoryName, options))
                {
                    if ((item.Type == FtpFileSystemObjectType.File) && (item.Name == path.GetFtpFileName()))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        ~FtpClient()
        {
            this.Dispose();
        }

        private void FireValidateCertficate(FtpSocketStream stream, FtpSslValidationEventArgs e)
        {
            this.OnValidateCertficate(e);
        }

        protected T GetAsyncDelegate<T>(IAsyncResult ar)
        {
            T local;
            lock (this.m_asyncmethods)
            {
                if (this.m_isDisposed)
                {
                    throw new ObjectDisposedException("This connection object has already been disposed.");
                }
                if (!this.m_asyncmethods.ContainsKey(ar))
                {
                    throw new InvalidOperationException("The specified IAsyncResult could not be located.");
                }
                if (!(this.m_asyncmethods[ar] is T))
                {
                    StackTrace trace = new StackTrace(1);
                    throw new InvalidCastException("The AsyncResult cannot be matched to the specified delegate. " + string.Format("Are you sure you meant to call {0} and not another method?", trace.GetFrame(0).GetMethod().Name));
                }
                local = (T) this.m_asyncmethods[ar];
                this.m_asyncmethods.Remove(ar);
            }
            return local;
        }

        protected virtual void GetFeatures(FtpReply reply)
        {
            foreach (string str in reply.InfoMessages.Split(new char[] { '\n' }))
            {
                if (str.ToUpper().Trim().StartsWith("MLST") || str.ToUpper().Trim().StartsWith("MLSD"))
                {
                    this.m_caps |= FtpCapability.MLSD;
                }
                else if (str.ToUpper().Trim().StartsWith("MDTM"))
                {
                    this.m_caps |= FtpCapability.MDTM;
                }
                else if (str.ToUpper().Trim().StartsWith("REST STREAM"))
                {
                    this.m_caps |= FtpCapability.REST;
                }
                else if (str.ToUpper().Trim().StartsWith("SIZE"))
                {
                    this.m_caps |= FtpCapability.SIZE;
                }
                else if (str.ToUpper().Trim().StartsWith("UTF8"))
                {
                    this.m_caps |= FtpCapability.UTF8;
                }
                else if (str.ToUpper().Trim().StartsWith("PRET"))
                {
                    this.m_caps |= FtpCapability.PRET;
                }
                else if (str.ToUpper().Trim().StartsWith("MFMT"))
                {
                    this.m_caps |= FtpCapability.MFMT;
                }
                else if (str.ToUpper().Trim().StartsWith("MFCT"))
                {
                    this.m_caps |= FtpCapability.MFCT;
                }
                else if (str.ToUpper().Trim().StartsWith("MFF"))
                {
                    this.m_caps |= FtpCapability.MFF;
                }
                else if (str.ToUpper().Trim().StartsWith("MD5"))
                {
                    this.m_caps |= FtpCapability.MD5;
                }
                else if (str.ToUpper().Trim().StartsWith("XMD5"))
                {
                    this.m_caps |= FtpCapability.XMD5;
                }
                else if (str.ToUpper().Trim().StartsWith("XCRC"))
                {
                    this.m_caps |= FtpCapability.XCRC;
                }
                else if (str.ToUpper().Trim().StartsWith("XSHA1"))
                {
                    this.m_caps |= FtpCapability.XSHA1;
                }
                else if (str.ToUpper().Trim().StartsWith("XSHA256"))
                {
                    this.m_caps |= FtpCapability.XSHA256;
                }
                else if (str.ToUpper().Trim().StartsWith("XSHA512"))
                {
                    this.m_caps |= FtpCapability.XSHA512;
                }
                else if (str.ToUpper().Trim().StartsWith("HASH"))
                {
                    Match match;
                    this.m_caps |= FtpCapability.HASH;
                    if ((match = Regex.Match(str.ToUpper().Trim(), @"^HASH\s+(?<types>.*)$")).Success)
                    {
                        foreach (string str2 in match.Groups["types"].Value.Split(new char[] { ';' }))
                        {
                            switch (str2.ToUpper().Trim())
                            {
                                case "SHA-1":
                                case "SHA-1*":
                                    this.m_hashAlgorithms |= FtpHashAlgorithm.SHA1;
                                    break;

                                case "SHA-256":
                                case "SHA-256*":
                                    this.m_hashAlgorithms |= FtpHashAlgorithm.SHA256;
                                    break;

                                case "SHA-512":
                                case "SHA-512*":
                                    this.m_hashAlgorithms |= FtpHashAlgorithm.SHA512;
                                    break;

                                case "MD5":
                                case "MD5*":
                                    this.m_hashAlgorithms |= FtpHashAlgorithm.MD5;
                                    break;

                                case "CRC":
                                case "CRC*":
                                    this.m_hashAlgorithms |= FtpHashAlgorithm.CRC;
                                    break;
                            }
                        }
                    }
                }
            }
        }

        public virtual long GetFileSize(string path)
        {
            long result = 0L;
            lock (this.m_lock)
            {
                FtpReply reply;
                FtpReply reply2 = reply = this.Execute("SIZE {0}", new object[] { path.GetFtpPath() });
                if (!reply2.Success)
                {
                    return -1L;
                }
                if (!long.TryParse(reply.Message, out result))
                {
                    return -1L;
                }
            }
            return result;
        }

        public FtpHash GetHash(string path)
        {
            FtpReply reply;
            Match match;
            FtpHash hash = new FtpHash();
            if (path == null)
            {
                throw new ArgumentException("GetHash(path) argument can't be null");
            }
            lock (this.m_lock)
            {
                FtpReply reply2 = reply = this.Execute("HASH {0}", new object[] { path.GetFtpPath() });
                if (!reply2.Success)
                {
                    throw new FtpCommandException(reply);
                }
            }
            if (!(match = Regex.Match(reply.Message, @"(?<algorithm>.+)\s(?<bytestart>\d+)-(?<byteend>\d+)\s(?<hash>.+)\s(?<filename>.+)")).Success)
            {
                match = Regex.Match(reply.Message, @"(?<algorithm>.+)\s(?<hash>.+)\s");
            }
            if ((match == null) || !match.Success)
            {
                FtpTrace.WriteLine("Failed to parse hash from: {0}", new object[] { reply.Message });
                return hash;
            }
            string str = match.Groups["algorithm"].Value;
            if (str != null)
            {
                if (!(str == "SHA-1"))
                {
                    if (str == "SHA-256")
                    {
                        hash.Algorithm = FtpHashAlgorithm.SHA256;
                        goto Label_0140;
                    }
                    if (str == "SHA-512")
                    {
                        hash.Algorithm = FtpHashAlgorithm.SHA512;
                        goto Label_0140;
                    }
                    if (str == "MD5")
                    {
                        hash.Algorithm = FtpHashAlgorithm.MD5;
                        goto Label_0140;
                    }
                }
                else
                {
                    hash.Algorithm = FtpHashAlgorithm.SHA1;
                    goto Label_0140;
                }
            }
            throw new NotImplementedException("Unknown hash algorithm: " + match.Groups["algorithm"].Value);
        Label_0140:
            hash.Value = match.Groups["hash"].Value;
            return hash;
        }

        public FtpHashAlgorithm GetHashAlgorithm()
        {
            FtpHashAlgorithm nONE = FtpHashAlgorithm.NONE;
            lock (this.m_lock)
            {
                FtpReply reply;
                string str;
                FtpReply reply2 = reply = this.Execute("OPTS HASH");
                if (!reply2.Success || ((str = reply.Message) == null))
                {
                    return nONE;
                }
                if (!(str == "SHA-1"))
                {
                    if (str != "SHA-256")
                    {
                        if (str == "SHA-512")
                        {
                            return FtpHashAlgorithm.SHA512;
                        }
                        if (str != "MD5")
                        {
                            return nONE;
                        }
                        goto Label_007D;
                    }
                }
                else
                {
                    return FtpHashAlgorithm.SHA1;
                }
                return FtpHashAlgorithm.SHA256;
            Label_007D:
                nONE = FtpHashAlgorithm.MD5;
            }
            return nONE;
        }

        public FtpListItem[] GetListing()
        {
            return this.GetListing(null);
        }

        public FtpListItem[] GetListing(string path)
        {
            return this.GetListing(path, 0);
        }

        public FtpListItem[] GetListing(string path, FtpListOption options)
        {
            FtpListItem item = null;
            List<FtpListItem> list = new List<FtpListItem>();
            List<string> list2 = new List<string>();
            string str = null;
            string workingDirectory = this.GetWorkingDirectory();
            string str3 = null;
            if ((path == null) || (path.Trim().Length == 0))
            {
                workingDirectory = this.GetWorkingDirectory();
                if ((workingDirectory != null) && (workingDirectory.Trim().Length > 0))
                {
                    path = workingDirectory;
                }
                else
                {
                    path = "./";
                }
            }
            else if ((!path.StartsWith("/") && (workingDirectory != null)) && (workingDirectory.Trim().Length > 0))
            {
                if (path.StartsWith("./"))
                {
                    path = path.Remove(0, 2);
                }
                path = string.Format("{0}/{1}", workingDirectory, path).GetFtpPath();
            }
            if (((options & FtpListOption.ForceList) != FtpListOption.ForceList) && this.HasFeature(FtpCapability.MLSD))
            {
                str = "MLSD";
            }
            else if ((options & FtpListOption.UseLS) == FtpListOption.UseLS)
            {
                str = "LS";
            }
            else if ((options & FtpListOption.NameList) == FtpListOption.NameList)
            {
                str = "NLST";
            }
            else
            {
                string str4 = "";
                str = "LIST";
                if ((options & FtpListOption.AllFiles) == FtpListOption.AllFiles)
                {
                    str4 = str4 + "a";
                }
                if ((options & FtpListOption.Recursive) == FtpListOption.Recursive)
                {
                    str4 = str4 + "R";
                }
                if (str4.Length > 0)
                {
                    str = str + " -" + str4;
                }
            }
            if ((options & FtpListOption.NoPath) != FtpListOption.NoPath)
            {
                str = string.Format("{0} {1}", str, path.GetFtpPath());
            }
            lock (this.m_lock)
            {
                this.Execute("TYPE I");
                using (System.Net.FtpClient.FtpDataStream stream = this.OpenDataStream(str, 0L))
                {
                    try
                    {
                        while ((str3 = stream.ReadLine(this.Encoding)) != null)
                        {
                            if (str3.Length > 0)
                            {
                                list2.Add(str3);
                                FtpTrace.WriteLine(str3);
                            }
                        }
                    }
                    finally
                    {
                        stream.Close();
                    }
                }
            }
            for (int i = 0; i < list2.Count; i++)
            {
                str3 = list2[i];
                if ((options & FtpListOption.NameList) == FtpListOption.NameList)
                {
                    item = new FtpListItem {
                        FullName = str3
                    };
                    if (this.DirectoryExists(item.FullName))
                    {
                        item.Type = FtpFileSystemObjectType.Directory;
                    }
                    else
                    {
                        item.Type = FtpFileSystemObjectType.File;
                    }
                    list.Add(item);
                }
                else
                {
                    if ((str.StartsWith("LIST") && ((options & FtpListOption.Recursive) == FtpListOption.Recursive)) && (str3.StartsWith("/") && str3.EndsWith(":")))
                    {
                        path = str3.TrimEnd(new char[] { ':' });
                        continue;
                    }
                    if (((i + 1) < list2.Count) && (list2[i + 1].StartsWith("\t") || list2[i + 1].StartsWith(" ")))
                    {
                        str3 = str3 + list2[++i];
                    }
                    item = FtpListItem.Parse(path, str3, this.m_caps);
                    if (((item != null) && (item.Name != ".")) && (item.Name != ".."))
                    {
                        list.Add(item);
                    }
                    else
                    {
                        FtpTrace.WriteLine("Failed to parse file listing: " + str3);
                    }
                }
                if (item != null)
                {
                    if ((item.Type == FtpFileSystemObjectType.Link) && ((options & FtpListOption.DerefLinks) == FtpListOption.DerefLinks))
                    {
                        item.LinkObject = this.DereferenceLink(item);
                    }
                    if ((((options & FtpListOption.Modify) == FtpListOption.Modify) && this.HasFeature(FtpCapability.MDTM)) && ((item.Modified == DateTime.MinValue) || str.StartsWith("LIST")))
                    {
                        DateTime time;
                        if (item.Type == FtpFileSystemObjectType.Directory)
                        {
                            FtpTrace.WriteLine("Trying to retrieve modification time of a directory, some servers don't like this...");
                        }
                        if ((time = this.GetModifiedTime(item.FullName)) != DateTime.MinValue)
                        {
                            item.Modified = time;
                        }
                    }
                    if ((((options & FtpListOption.Size) == FtpListOption.Size) && this.HasFeature(FtpCapability.SIZE)) && (item.Size == -1L))
                    {
                        if (item.Type != FtpFileSystemObjectType.Directory)
                        {
                            item.Size = this.GetFileSize(item.FullName);
                        }
                        else
                        {
                            item.Size = 0L;
                        }
                    }
                }
            }
            return list.ToArray();
        }

        public virtual DateTime GetModifiedTime(string path)
        {
            DateTime minValue = DateTime.MinValue;
            lock (this.m_lock)
            {
                FtpReply reply;
                FtpReply reply2 = reply = this.Execute("MDTM {0}", new object[] { path.GetFtpPath() });
                if (reply2.Success)
                {
                    minValue = reply.Message.GetFtpDate(DateTimeStyles.AssumeUniversal);
                }
            }
            return minValue;
        }

        public string[] GetNameListing()
        {
            return this.GetNameListing(null);
        }

        public string[] GetNameListing(string path)
        {
            List<string> list = new List<string>();
            string workingDirectory = this.GetWorkingDirectory();
            path = path.GetFtpPath();
            if ((path == null) || (path.Trim().Length == 0))
            {
                if ((workingDirectory != null) && (workingDirectory.Trim().Length > 0))
                {
                    path = workingDirectory;
                }
                else
                {
                    path = "./";
                }
            }
            else if ((!path.StartsWith("/") && (workingDirectory != null)) && (workingDirectory.Trim().Length > 0))
            {
                if (path.StartsWith("./"))
                {
                    path = path.Remove(0, 2);
                }
                path = string.Format("{0}/{1}", workingDirectory, path).GetFtpPath();
            }
            lock (this.m_lock)
            {
                this.Execute("TYPE I");
                using (System.Net.FtpClient.FtpDataStream stream = this.OpenDataStream(string.Format("NLST {0}", path.GetFtpPath()), 0L))
                {
                    try
                    {
                        string str2;
                        while ((str2 = stream.ReadLine(this.Encoding)) != null)
                        {
                            list.Add(str2);
                        }
                    }
                    finally
                    {
                        stream.Close();
                    }
                }
            }
            return list.ToArray();
        }

        public FtpListItem GetObjectInfo(string path)
        {
            FtpReply reply;
            if ((this.Capabilities & FtpCapability.MLSD) != FtpCapability.MLSD)
            {
                throw new InvalidOperationException("The GetObjectInfo method only works on servers that support machine listings. Please check the Capabilities flags for FtpCapability.MLSD before calling this method.");
            }
            FtpReply reply2 = reply = this.Execute("MLST {0}", new object[] { path });
            if (reply2.Success)
            {
                string[] strArray = reply.InfoMessages.Split(new char[] { '\n' });
                if (strArray.Length > 1)
                {
                    string buf = "";
                    for (int i = 1; i < strArray.Length; i++)
                    {
                        buf = buf + strArray[i];
                    }
                    return FtpListItem.Parse(null, buf, this.m_caps);
                }
            }
            else
            {
                FtpTrace.WriteLine("Failed to get object info for path {0} with error {1}", new object[] { path, reply.ErrorMessage });
            }
            return null;
        }

        internal FtpReply GetReply()
        {
            FtpReply reply = new FtpReply();
            lock (this.m_lock)
            {
                string str;
                if (!this.IsConnected)
                {
                    throw new InvalidOperationException("No connection to the server has been established.");
                }
                this.m_stream.ReadTimeout = this.m_readTimeout;
                while ((str = this.m_stream.ReadLine(this.Encoding)) != null)
                {
                    Match match;
                    FtpTrace.WriteLine(str);
                    if ((match = Regex.Match(str, "^(?<code>[0-9]{3}) (?<message>.*)$")).Success)
                    {
                        reply.Code = match.Groups["code"].Value;
                        reply.Message = match.Groups["message"].Value;
                        return reply;
                    }
                    reply.InfoMessages = reply.InfoMessages + string.Format("{0}\n", str);
                }
            }
            return reply;
        }

        public string GetWorkingDirectory()
        {
            FtpReply reply;
            Match match;
            lock (this.m_lock)
            {
                FtpReply reply2 = reply = this.Execute("PWD");
                if (!reply2.Success)
                {
                    throw new FtpCommandException(reply);
                }
            }
            if ((match = Regex.Match(reply.Message, "\"(?<pwd>.*)\"")).Success)
            {
                return match.Groups["pwd"].Value;
            }
            if ((match = Regex.Match(reply.Message, "PWD = (?<pwd>.*)")).Success)
            {
                return match.Groups["pwd"].Value;
            }
            FtpTrace.WriteLine("Failed to parse working directory from: " + reply.Message);
            return "./";
        }

        public bool HasFeature(FtpCapability cap)
        {
            return ((this.Capabilities & cap) == cap);
        }

        private void OnValidateCertficate(FtpSslValidationEventArgs e)
        {
            FtpSslValidation sslvalidate = this.m_sslvalidate;
            if (sslvalidate != null)
            {
                sslvalidate(this, e);
            }
        }

        private void m_sslvalidate(FtpClient control, FtpSslValidationEventArgs e)
        {
            throw new NotImplementedException();
        }

        private System.Net.FtpClient.FtpDataStream OpenActiveDataStream(FtpDataConnectionType type, string command, long restart)
        {
            FtpReply reply;
            System.Net.FtpClient.FtpDataStream stream = new System.Net.FtpClient.FtpDataStream(this);
            if (this.m_stream == null)
            {
                throw new InvalidOperationException("The control connection stream is null! Generally this means there is no connection to the server. Cannot open an active data stream.");
            }
            stream.Listen(this.m_stream.LocalEndPoint.Address, 0);
            IAsyncResult ar = stream.BeginAccept(null, null);
            if ((type != FtpDataConnectionType.EPRT) && (type != FtpDataConnectionType.AutoActive))
            {
                if (this.m_stream.LocalEndPoint.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new FtpException("Only IPv4 is supported by the PORT command. Use EPRT instead.");
                }
                FtpReply reply3 = reply = this.Execute("PORT {0},{1},{2}", new object[] { stream.LocalEndPoint.Address.ToString().Replace('.', ','), stream.LocalEndPoint.Port / 0x100, stream.LocalEndPoint.Port % 0x100 });
                if (!reply3.Success)
                {
                    stream.Close();
                    throw new FtpCommandException(reply);
                }
                goto Label_01B9;
            }
            int num = 0;
            AddressFamily addressFamily = stream.LocalEndPoint.AddressFamily;
            if (addressFamily != AddressFamily.InterNetwork)
            {
                if (addressFamily != AddressFamily.InterNetworkV6)
                {
                    throw new InvalidOperationException("The IP protocol being used is not supported.");
                }
            }
            else
            {
                num = 1;
                goto Label_0074;
            }
            num = 2;
        Label_0074:;
            FtpReply reply2 = reply = this.Execute("EPRT |{0}|{1}|{2}|", new object[] { num, stream.LocalEndPoint.Address.ToString(), stream.LocalEndPoint.Port });
            if (!reply2.Success)
            {
                if (((reply.Type == FtpResponseType.PermanentNegativeCompletion) && (type == FtpDataConnectionType.AutoActive)) && ((this.m_stream != null) && (this.m_stream.LocalEndPoint.AddressFamily == AddressFamily.InterNetwork)))
                {
                    stream.ControlConnection = null;
                    stream.Close();
                    return this.OpenActiveDataStream(FtpDataConnectionType.PORT, command, restart);
                }
                stream.Close();
                throw new FtpCommandException(reply);
            }
        Label_01B9:
            if (restart > 0L)
            {
                FtpReply reply4 = reply = this.Execute("REST {0}", new object[] { restart });
                if (!reply4.Success)
                {
                    throw new FtpCommandException(reply);
                }
            }
            FtpReply reply5 = reply = this.Execute(command);
            if (!reply5.Success)
            {
                stream.Close();
                throw new FtpCommandException(reply);
            }
            stream.CommandStatus = reply;
            ar.AsyncWaitHandle.WaitOne(this.m_dataConnectionConnectTimeout);
            if (!ar.IsCompleted)
            {
                stream.Close();
                throw new TimeoutException("Timed out waiting for the server to connect to the active data socket.");
            }
            stream.EndAccept(ar);
            if (this.m_dataConnectionEncryption && (this.m_encryptionmode != FtpEncryptionMode.None))
            {
                stream.ActivateEncryption(this.m_host, (this.ClientCertificates.Count > 0) ? this.ClientCertificates : null, this.m_SslProtocols);
            }
            stream.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, this.m_keepAlive);
            stream.ReadTimeout = this.m_dataConnectionReadTimeout;
            return stream;
        }

        public Stream OpenAppend(string path)
        {
            return this.OpenAppend(path, FtpDataType.Binary);
        }

        public static Stream OpenAppend(Uri uri)
        {
            return OpenAppend(uri, true, FtpDataType.Binary);
        }

        public virtual Stream OpenAppend(string path, FtpDataType type)
        {
            System.Net.FtpClient.FtpClient client = null;
            System.Net.FtpClient.FtpDataStream stream = null;
            long fileSize = 0L;
            lock (this.m_lock)
            {
                if (this.m_threadSafeDataChannels)
                {
                    client = this.CloneConnection();
                    client.Connect();
                    client.SetWorkingDirectory(this.GetWorkingDirectory());
                }
                else
                {
                    client = this;
                }
                client.SetDataType(type);
                fileSize = client.GetFileSize(path);
                stream = client.OpenDataStream(string.Format("APPE {0}", path.GetFtpPath()), 0L);
                if ((fileSize > 0L) && (stream != null))
                {
                    stream.SetLength(fileSize);
                    stream.SetPosition(fileSize);
                }
            }
            return stream;
        }

        public static Stream OpenAppend(Uri uri, bool checkcertificate)
        {
            return OpenAppend(uri, checkcertificate, FtpDataType.Binary);
        }

        public static Stream OpenAppend(Uri uri, bool checkcertificate, FtpDataType datatype)
        {
            System.Net.FtpClient.FtpClient client = null;
            if ((uri.PathAndQuery == null) || (uri.PathAndQuery.Length == 0))
            {
                throw new UriFormatException("The supplied URI does not contain a valid path.");
            }
            if (uri.PathAndQuery.EndsWith("/"))
            {
                throw new UriFormatException("The supplied URI points at a directory.");
            }
            client = Connect(uri, checkcertificate);
            client.EnableThreadSafeDataConnections = false;
            return client.OpenAppend(uri.PathAndQuery, datatype);
        }

        private System.Net.FtpClient.FtpDataStream OpenDataStream(string command, long restart)
        {
            FtpDataConnectionType dataConnectionType = this.m_dataConnectionType;
            System.Net.FtpClient.FtpDataStream stream = null;
            lock (this.m_lock)
            {
                if (!this.IsConnected)
                {
                    this.Connect();
                }
                if (this.m_stream.LocalEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    switch (dataConnectionType)
                    {
                        case FtpDataConnectionType.PASV:
                        case FtpDataConnectionType.PASVEX:
                            dataConnectionType = FtpDataConnectionType.EPSV;
                            FtpTrace.WriteLine("Changed data connection type to EPSV because we are connected with IPv6.");
                            break;

                        case FtpDataConnectionType.PORT:
                            dataConnectionType = FtpDataConnectionType.EPRT;
                            FtpTrace.WriteLine("Changed data connection type to EPRT because we are connected with IPv6.");
                            break;
                    }
                }
                switch (dataConnectionType)
                {
                    case FtpDataConnectionType.AutoPassive:
                    case FtpDataConnectionType.PASV:
                    case FtpDataConnectionType.PASVEX:
                    case FtpDataConnectionType.EPSV:
                        stream = this.OpenPassiveDataStream(dataConnectionType, command, restart);
                        break;

                    case FtpDataConnectionType.AutoActive:
                    case FtpDataConnectionType.PORT:
                    case FtpDataConnectionType.EPRT:
                        stream = this.OpenActiveDataStream(dataConnectionType, command, restart);
                        break;
                }
                if (stream == null)
                {
                    throw new InvalidOperationException("The specified data channel type is not implemented.");
                }
            }
            return stream;
        }

        private System.Net.FtpClient.FtpDataStream OpenPassiveDataStream(FtpDataConnectionType type, string command, long restart)
        {
            System.Net.FtpClient.FtpDataStream stream = null;
            FtpReply reply;
            Match match;
            string host = null;
            int port = 0;
            if (this.m_stream == null)
            {
                throw new InvalidOperationException("The control connection stream is null! Generally this means there is no connection to the server. Cannot open a passive data stream.");
            }
            if ((type == FtpDataConnectionType.EPSV) || (type == FtpDataConnectionType.AutoPassive))
            {
                FtpReply reply2 = reply = this.Execute("EPSV");
                if (!reply2.Success)
                {
                    if (((reply.Type != FtpResponseType.PermanentNegativeCompletion) || (type != FtpDataConnectionType.AutoPassive)) || ((this.m_stream == null) || (this.m_stream.LocalEndPoint.AddressFamily != AddressFamily.InterNetwork)))
                    {
                        throw new FtpCommandException(reply);
                    }
                    return this.OpenPassiveDataStream(FtpDataConnectionType.PASV, command, restart);
                }
                match = Regex.Match(reply.Message, @"\(\|\|\|(?<port>\d+)\|\)");
                if (!match.Success)
                {
                    throw new FtpException("Failed to get the EPSV port from: " + reply.Message);
                }
                host = this.m_host;
                port = int.Parse(match.Groups["port"].Value);
            }
            else
            {
                if (this.m_stream.LocalEndPoint.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new FtpException("Only IPv4 is supported by the PASV command. Use EPSV instead.");
                }
                FtpReply reply3 = reply = this.Execute("PASV");
                if (!reply3.Success)
                {
                    throw new FtpCommandException(reply);
                }
                match = Regex.Match(reply.Message, @"(?<quad1>\d+),(?<quad2>\d+),(?<quad3>\d+),(?<quad4>\d+),(?<port1>\d+),(?<port2>\d+)");
                if (!match.Success || (match.Groups.Count != 7))
                {
                    throw new FtpException(string.Format("Malformed PASV response: {0}", reply.Message));
                }
                if (type == FtpDataConnectionType.PASVEX)
                {
                    host = this.m_host;
                }
                else
                {
                    host = string.Format("{0}.{1}.{2}.{3}", new object[] { match.Groups["quad1"].Value, match.Groups["quad2"].Value, match.Groups["quad3"].Value, match.Groups["quad4"].Value });
                }
                port = (int.Parse(match.Groups["port1"].Value) << 8) + int.Parse(match.Groups["port2"].Value);
            }
            stream = new System.Net.FtpClient.FtpDataStream(this) {
                ConnectTimeout = this.DataConnectionConnectTimeout,
                ReadTimeout = this.DataConnectionReadTimeout
            };
            stream.Connect(host, port, this.InternetProtocolVersions);
            stream.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, this.m_keepAlive);
            if (restart > 0L)
            {
                FtpReply reply4 = reply = this.Execute("REST {0}", new object[] { restart });
                if (!reply4.Success)
                {
                    throw new FtpCommandException(reply);
                }
            }
            FtpReply reply5 = reply = this.Execute(command);
            if (!reply5.Success)
            {
                stream.Close();
                throw new FtpCommandException(reply);
            }
            stream.CommandStatus = reply;
            if (this.m_dataConnectionEncryption && (this.m_encryptionmode != FtpEncryptionMode.None))
            {
                stream.ActivateEncryption(this.m_host, (this.ClientCertificates.Count > 0) ? this.ClientCertificates : null, this.m_SslProtocols);
            }
            return stream;
        }

        public Stream OpenRead(string path)
        {
            return this.OpenRead(path, FtpDataType.Binary, 0L);
        }

        public static Stream OpenRead(Uri uri)
        {
            return OpenRead(uri, true, FtpDataType.Binary, 0L);
        }

        public Stream OpenRead(string path, long restart)
        {
            return this.OpenRead(path, FtpDataType.Binary, restart);
        }

        public Stream OpenRead(string path, FtpDataType type)
        {
            return this.OpenRead(path, type, 0L);
        }

        public static Stream OpenRead(Uri uri, bool checkcertificate)
        {
            return OpenRead(uri, checkcertificate, FtpDataType.Binary, 0L);
        }

        public virtual Stream OpenRead(string path, FtpDataType type, long restart)
        {
            System.Net.FtpClient.FtpClient client = null;
            System.Net.FtpClient.FtpDataStream stream = null;
            long fileSize = 0L;
            lock (this.m_lock)
            {
                if (this.m_threadSafeDataChannels)
                {
                    client = this.CloneConnection();
                    client.Connect();
                    client.SetWorkingDirectory(this.GetWorkingDirectory());
                }
                else
                {
                    client = this;
                }
                client.SetDataType(type);
                fileSize = client.GetFileSize(path);
                stream = client.OpenDataStream(string.Format("RETR {0}", path.GetFtpPath()), restart);
            }
            if (stream != null)
            {
                if (fileSize > 0L)
                {
                    stream.SetLength(fileSize);
                }
                if (restart > 0L)
                {
                    stream.SetPosition(restart);
                }
            }
            return stream;
        }

        public static Stream OpenRead(Uri uri, bool checkcertificate, FtpDataType datatype)
        {
            return OpenRead(uri, checkcertificate, datatype, 0L);
        }

        public static Stream OpenRead(Uri uri, bool checkcertificate, FtpDataType datatype, long restart)
        {
            System.Net.FtpClient.FtpClient client = null;
            if ((uri.PathAndQuery == null) || (uri.PathAndQuery.Length == 0))
            {
                throw new UriFormatException("The supplied URI does not contain a valid path.");
            }
            if (uri.PathAndQuery.EndsWith("/"))
            {
                throw new UriFormatException("The supplied URI points at a directory.");
            }
            client = Connect(uri, checkcertificate);
            client.EnableThreadSafeDataConnections = false;
            return client.OpenRead(uri.PathAndQuery, datatype, restart);
        }

        public Stream OpenWrite(string path)
        {
            return this.OpenWrite(path, FtpDataType.Binary);
        }

        public static Stream OpenWrite(Uri uri)
        {
            return OpenWrite(uri, true, FtpDataType.Binary);
        }

        public virtual Stream OpenWrite(string path, FtpDataType type)
        {
            System.Net.FtpClient.FtpClient client = null;
            System.Net.FtpClient.FtpDataStream stream = null;
            long fileSize = 0L;
            lock (this.m_lock)
            {
                if (this.m_threadSafeDataChannels)
                {
                    client = this.CloneConnection();
                    client.Connect();
                    client.SetWorkingDirectory(this.GetWorkingDirectory());
                }
                else
                {
                    client = this;
                }
                client.SetDataType(type);
                fileSize = client.GetFileSize(path);
                stream = client.OpenDataStream(string.Format("STOR {0}", path.GetFtpPath()), 0L);
                if ((fileSize > 0L) && (stream != null))
                {
                    stream.SetLength(fileSize);
                }
            }
            return stream;
        }

        public static Stream OpenWrite(Uri uri, bool checkcertificate)
        {
            return OpenWrite(uri, checkcertificate, FtpDataType.Binary);
        }

        public static Stream OpenWrite(Uri uri, bool checkcertificate, FtpDataType datatype)
        {
            System.Net.FtpClient.FtpClient client = null;
            if ((uri.PathAndQuery == null) || (uri.PathAndQuery.Length == 0))
            {
                throw new UriFormatException("The supplied URI does not contain a valid path.");
            }
            if (uri.PathAndQuery.EndsWith("/"))
            {
                throw new UriFormatException("The supplied URI points at a directory.");
            }
            client = Connect(uri, checkcertificate);
            client.EnableThreadSafeDataConnections = false;
            return client.OpenWrite(uri.PathAndQuery, datatype);
        }

        public void Rename(string path, string dest)
        {
            lock (this.m_lock)
            {
                FtpReply reply;
                FtpReply reply2 = reply = this.Execute("RNFR {0}", new object[] { path.GetFtpPath() });
                if (!reply2.Success)
                {
                    throw new FtpCommandException(reply);
                }
                FtpReply reply3 = reply = this.Execute("RNTO {0}", new object[] { dest.GetFtpPath() });
                if (!reply3.Success)
                {
                    throw new FtpCommandException(reply);
                }
            }
        }

        protected void SetDataType(FtpDataType type)
        {
            lock (this.m_lock)
            {
                FtpReply reply;
                switch (type)
                {
                    case FtpDataType.ASCII:
                    {
                        FtpReply reply2 = reply = this.Execute("TYPE A");
                        if (!reply2.Success)
                        {
                            throw new FtpCommandException(reply);
                        }
                        break;
                    }
                    case FtpDataType.Binary:
                    {
                        FtpReply reply3 = reply = this.Execute("TYPE I");
                        if (!reply3.Success)
                        {
                            throw new FtpCommandException(reply);
                        }
                        break;
                    }
                    default:
                        throw new FtpException("Unsupported data type: " + type.ToString());
                }
            }
        }

        public void SetHashAlgorithm(FtpHashAlgorithm type)
        {
            lock (this.m_lock)
            {
                FtpReply reply;
                string str;
                if ((this.HashAlgorithms & type) != type)
                {
                    throw new NotImplementedException(string.Format("The hash algorithm {0} was not advertised by the server.", type.ToString()));
                }
                switch (type)
                {
                    case FtpHashAlgorithm.SHA1:
                        str = "SHA-1";
                        break;

                    case FtpHashAlgorithm.SHA256:
                        str = "SHA-256";
                        break;

                    case FtpHashAlgorithm.SHA512:
                        str = "SHA-512";
                        break;

                    case FtpHashAlgorithm.MD5:
                        str = "MD5";
                        break;

                    default:
                        str = type.ToString();
                        break;
                }
                FtpReply reply2 = reply = this.Execute("OPTS HASH {0}", new object[] { str });
                if (!reply2.Success)
                {
                    throw new FtpCommandException(reply);
                }
            }
        }

        public void SetWorkingDirectory(string path)
        {
            string ftpPath = path.GetFtpPath();
            switch (ftpPath)
            {
                case ".":
                case "./":
                    return;
            }
            lock (this.m_lock)
            {
                FtpReply reply;
                FtpReply reply2 = reply = this.Execute("CWD {0}", new object[] { ftpPath });
                if (!reply2.Success)
                {
                    throw new FtpCommandException(reply);
                }
            }
        }

        protected Stream BaseStream
        {
            get
            {
                return this.m_stream;
            }
        }

        [FtpControlConnectionClone]
        public FtpCapability Capabilities
        {
            get
            {
                if ((this.m_stream == null) || !this.m_stream.IsConnected)
                {
                    this.Connect();
                }
                return this.m_caps;
            }
            protected set
            {
                this.m_caps = value;
            }
        }

        [FtpControlConnectionClone]
        public X509CertificateCollection ClientCertificates
        {
            get
            {
                return this.m_clientCerts;
            }
            protected set
            {
                this.m_clientCerts = value;
            }
        }

        [FtpControlConnectionClone]
        public int ConnectTimeout
        {
            get
            {
                return this.m_connectTimeout;
            }
            set
            {
                this.m_connectTimeout = value;
            }
        }

        [FtpControlConnectionClone]
        public NetworkCredential Credentials
        {
            get
            {
                return this.m_credentials;
            }
            set
            {
                this.m_credentials = value;
            }
        }

        [FtpControlConnectionClone]
        public int DataConnectionConnectTimeout
        {
            get
            {
                return this.m_dataConnectionConnectTimeout;
            }
            set
            {
                this.m_dataConnectionConnectTimeout = value;
            }
        }

        [FtpControlConnectionClone]
        public bool DataConnectionEncryption
        {
            get
            {
                return this.m_dataConnectionEncryption;
            }
            set
            {
                this.m_dataConnectionEncryption = value;
            }
        }

        [FtpControlConnectionClone]
        public int DataConnectionReadTimeout
        {
            get
            {
                return this.m_dataConnectionReadTimeout;
            }
            set
            {
                this.m_dataConnectionReadTimeout = value;
            }
        }

        [FtpControlConnectionClone]
        public FtpDataConnectionType DataConnectionType
        {
            get
            {
                return this.m_dataConnectionType;
            }
            set
            {
                this.m_dataConnectionType = value;
            }
        }

        [FtpControlConnectionClone]
        public bool EnableThreadSafeDataConnections
        {
            get
            {
                return this.m_threadSafeDataChannels;
            }
            set
            {
                this.m_threadSafeDataChannels = value;
            }
        }

        [FtpControlConnectionClone]
        public System.Text.Encoding Encoding
        {
            get
            {
                return this.m_textEncoding;
            }
            set
            {
                lock (this.m_lock)
                {
                    this.m_textEncoding = value;
                }
            }
        }

        [FtpControlConnectionClone]
        public FtpEncryptionMode EncryptionMode
        {
            get
            {
                return this.m_encryptionmode;
            }
            set
            {
                this.m_encryptionmode = value;
            }
        }

        public FtpHashAlgorithm HashAlgorithms
        {
            get
            {
                if ((this.m_stream == null) || !this.m_stream.IsConnected)
                {
                    this.Connect();
                }
                return this.m_hashAlgorithms;
            }
            private set
            {
                this.m_hashAlgorithms = value;
            }
        }

        [FtpControlConnectionClone]
        public string Host
        {
            get
            {
                return this.m_host;
            }
            set
            {
                this.m_host = value;
            }
        }

        [FtpControlConnectionClone]
        public FtpIpVersion InternetProtocolVersions
        {
            get
            {
                return this.m_ipVersions;
            }
            set
            {
                this.m_ipVersions = value;
            }
        }

        internal bool IsClone
        {
            get
            {
                return this.m_isClone;
            }
            private set
            {
                this.m_isClone = value;
            }
        }

        public bool IsConnected
        {
            get
            {
                return ((this.m_stream != null) && this.m_stream.IsConnected);
            }
        }

        public bool IsDisposed
        {
            get
            {
                return this.m_isDisposed;
            }
            private set
            {
                this.m_isDisposed = value;
            }
        }

        [FtpControlConnectionClone]
        public int MaximumDereferenceCount
        {
            get
            {
                return this.m_maxDerefCount;
            }
            set
            {
                this.m_maxDerefCount = value;
            }
        }

        [FtpControlConnectionClone]
        public int Port
        {
            get
            {
                if (this.m_port == 0)
                {
                    switch (this.EncryptionMode)
                    {
                        case FtpEncryptionMode.None:
                        case FtpEncryptionMode.Explicit:
                            return 0x15;

                        case FtpEncryptionMode.Implicit:
                            return 990;
                    }
                }
                return this.m_port;
            }
            set
            {
                this.m_port = value;
            }
        }

        [FtpControlConnectionClone]
        public int ReadTimeout
        {
            get
            {
                return this.m_readTimeout;
            }
            set
            {
                this.m_readTimeout = value;
            }
        }

        [FtpControlConnectionClone]
        public bool SocketKeepAlive
        {
            get
            {
                return this.m_keepAlive;
            }
            set
            {
                this.m_keepAlive = value;
                if (this.m_stream != null)
                {
                    this.m_stream.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, value);
                }
            }
        }

        [FtpControlConnectionClone]
        public int SocketPollInterval
        {
            get
            {
                return this.m_socketPollInterval;
            }
            set
            {
                this.m_socketPollInterval = value;
                if (this.m_stream != null)
                {
                    this.m_stream.SocketPollInterval = value;
                }
            }
        }

        [FtpControlConnectionClone]
        public System.Security.Authentication.SslProtocols SslProtocols
        {
            get
            {
                return this.m_SslProtocols;
            }
            set
            {
                this.m_SslProtocols = value;
            }
        }

        [FtpControlConnectionClone]
        public bool StaleDataCheck
        {
            get
            {
                return this.m_staleDataTest;
            }
            set
            {
                this.m_staleDataTest = value;
            }
        }

        public string SystemType
        {
            get
            {
                FtpReply reply = this.Execute("SYST");
                if (reply.Success)
                {
                    return reply.Message;
                }
                return null;
            }
        }

        [FtpControlConnectionClone]
        public bool UngracefullDisconnection
        {
            get
            {
                return this.m_ungracefullDisconnect;
            }
            set
            {
                this.m_ungracefullDisconnect = value;
            }
        }

        private delegate void AsyncConnect();

        private delegate void AsyncCreateDirectory(string path, bool force);

        private delegate void AsyncDeleteDirectory(string path, bool force, FtpListOption options);

        private delegate void AsyncDeleteFile(string path);

        private delegate FtpListItem AsyncDereferenceLink(FtpListItem item, int recMax);

        private delegate bool AsyncDirectoryExists(string path);

        private delegate void AsyncDisconnect();

        private delegate FtpReply AsyncExecute(string command);

        private delegate bool AsyncFileExists(string path, FtpListOption options);

        private delegate long AsyncGetFileSize(string path);

        private delegate FtpHash AsyncGetHash(string path);

        private delegate FtpHashAlgorithm AsyncGetHashAlgorithm();

        private delegate FtpListItem[] AsyncGetListing(string path, FtpListOption options);

        private delegate DateTime AsyncGetModifiedTime(string path);

        private delegate string[] AsyncGetNameListing(string path);

        private delegate FtpListItem AsyncGetObjectInfo(string path);

        private delegate string AsyncGetWorkingDirectory();

        private delegate Stream AsyncOpenAppend(string path, FtpDataType type);

        private delegate Stream AsyncOpenRead(string path, FtpDataType type, long restart);

        private delegate Stream AsyncOpenWrite(string path, FtpDataType type);

        private delegate void AsyncRename(string path, string dest);

        private delegate void AsyncSetDataType(FtpDataType type);

        private delegate void AsyncSetHashAlgorithm(FtpHashAlgorithm type);

        private delegate void AsyncSetWorkingDirectory(string path);

        private sealed class FtpControlConnectionClone : Attribute
        {
        }
    }
}

