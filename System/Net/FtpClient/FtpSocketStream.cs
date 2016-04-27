namespace System.Net.FtpClient
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;

    public class FtpSocketStream : Stream, IDisposable
    {
        private int m_connectTimeout = 0x7530;
        private DateTime m_lastActivity = DateTime.Now;
        private System.Net.Sockets.NetworkStream m_netStream;
        private int m_readTimeout = -1;
        private System.Net.Sockets.Socket m_socket;
        private int m_socketPollInterval = 0x3a98;
        private System.Net.Security.SslStream m_sslStream;

        private event FtpSocketStreamSslValidation m_sslvalidate;

        public event FtpSocketStreamSslValidation ValidateCertificate
        {
            add
            {
                this.m_sslvalidate += value;
            }
            remove
            {
                this.m_sslvalidate -= value;
            }
        }

        public void Accept()
        {
            if (this.m_socket != null)
            {
                this.m_socket = this.m_socket.Accept();
            }
        }

        public void ActivateEncryption(string targethost)
        {
            this.ActivateEncryption(targethost, null, SslProtocols.Default);
        }

        public void ActivateEncryption(string targethost, X509CertificateCollection clientCerts)
        {
            this.ActivateEncryption(targethost, clientCerts, SslProtocols.Default);
        }

        public void ActivateEncryption(string targethost, X509CertificateCollection clientCerts, SslProtocols sslProtocols)
        {
            RemoteCertificateValidationCallback userCertificateValidationCallback = null;
            if (!this.IsConnected)
            {
                throw new InvalidOperationException("The FtpSocketStream object is not connected.");
            }
            if (this.m_netStream == null)
            {
                throw new InvalidOperationException("The base network stream is null.");
            }
            if (this.m_sslStream != null)
            {
                throw new InvalidOperationException("SSL Encryption has already been enabled on this stream.");
            }
            try
            {
                if (userCertificateValidationCallback == null)
                {
                    userCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => this.OnValidateCertificate(certificate, chain, sslPolicyErrors);
                }
                this.m_sslStream = new System.Net.Security.SslStream(this.NetworkStream, true, userCertificateValidationCallback);
                DateTime now = DateTime.Now;
                this.m_sslStream.AuthenticateAsClient(targethost, clientCerts, sslProtocols, true);
                TimeSpan span = DateTime.Now.Subtract(now);
                FtpTrace.WriteLine("Time to activate encryption: {0}h {1}m {2}s, Total Seconds: {3}.", new object[] { span.Hours, span.Minutes, span.Seconds, span.TotalSeconds });
            }
            catch (AuthenticationException exception)
            {
                this.Close();
                throw exception;
            }
        }

        public IAsyncResult BeginAccept(AsyncCallback callback, object state)
        {
            if (this.m_socket != null)
            {
                return this.m_socket.BeginAccept(callback, state);
            }
            return null;
        }

        public override void Close()
        {
            if (this.m_socket != null)
            {
                try
                {
                    if (this.m_socket.Connected)
                    {
                        this.m_socket.Close();
                    }
                    this.m_socket.Dispose();
                }
                catch (SocketException exception)
                {
                    FtpTrace.WriteLine("Caught and discarded a SocketException while cleaning up the Socket: {0}", new object[] { exception.ToString() });
                }
                finally
                {
                    this.m_socket = null;
                }
            }
            if (this.m_netStream != null)
            {
                try
                {
                    this.m_netStream.Dispose();
                }
                catch (IOException exception2)
                {
                    FtpTrace.WriteLine("Caught and discarded an IOException while cleaning up the NetworkStream: {0}", new object[] { exception2.ToString() });
                }
                finally
                {
                    this.m_netStream = null;
                }
            }
            if (this.m_sslStream != null)
            {
                try
                {
                    this.m_sslStream.Dispose();
                }
                catch (IOException exception3)
                {
                    FtpTrace.WriteLine("Caught and discarded an IOException while cleaning up the SslStream: {0}", new object[] { exception3.ToString() });
                }
                finally
                {
                    this.m_sslStream = null;
                }
            }
        }

        public void Connect(string host, int port, FtpIpVersion ipVersions)
        {
            IAsyncResult asyncResult = null;
            IPAddress[] hostAddresses = Dns.GetHostAddresses(host);
            if (ipVersions == 0)
            {
                throw new ArgumentException("The ipVersions parameter must contain at least 1 flag.");
            }
            for (int i = 0; i < hostAddresses.Length; i++)
            {
                if (ipVersions == FtpIpVersion.ANY)
                {
                    goto Label_0044;
                }
                AddressFamily addressFamily = hostAddresses[i].AddressFamily;
                if (addressFamily != AddressFamily.InterNetwork)
                {
                    if (addressFamily == AddressFamily.InterNetworkV6)
                    {
                        goto Label_003E;
                    }
                    goto Label_0044;
                }
                if ((ipVersions & FtpIpVersion.IPv4) == FtpIpVersion.IPv4)
                {
                    goto Label_0044;
                }
                continue;
            Label_003E:
                if ((ipVersions & FtpIpVersion.IPv6) != FtpIpVersion.IPv6)
                {
                    continue;
                }
            Label_0044:
                this.m_socket = new System.Net.Sockets.Socket(hostAddresses[i].AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                asyncResult = this.m_socket.BeginConnect(hostAddresses[i], port, null, null);
                if (!asyncResult.AsyncWaitHandle.WaitOne(this.m_connectTimeout, true))
                {
                    this.Close();
                    if ((i + 1) == hostAddresses.Length)
                    {
                        throw new TimeoutException("Timed out trying to connect!");
                    }
                }
                else
                {
                    this.m_socket.EndConnect(asyncResult);
                    break;
                }
            }
            if ((this.m_socket == null) || !this.m_socket.Connected)
            {
                this.Close();
                throw new IOException("Failed to connect to host.");
            }
            this.m_netStream = new System.Net.Sockets.NetworkStream(this.m_socket);
            this.m_lastActivity = DateTime.Now;
        }

        public void Dispose()
        {
            FtpTrace.WriteLine("Disposing FtpSocketStream...");
            this.Close();
        }

        public void EndAccept(IAsyncResult ar)
        {
            if (this.m_socket != null)
            {
                this.m_socket = this.m_socket.EndAccept(ar);
                this.m_netStream = new System.Net.Sockets.NetworkStream(this.m_socket);
            }
        }

        public override void Flush()
        {
            if (!this.IsConnected)
            {
                throw new InvalidOperationException("The FtpSocketStream object is not connected.");
            }
            if (this.BaseStream == null)
            {
                throw new InvalidOperationException("The base stream of the FtpSocketStream object is null.");
            }
            this.BaseStream.Flush();
        }

        public void Listen(IPAddress address, int port)
        {
            if (!this.IsConnected)
            {
                if (this.m_socket == null)
                {
                    this.m_socket = new System.Net.Sockets.Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                }
                this.m_socket.Bind(new IPEndPoint(address, port));
                this.m_socket.Listen(1);
            }
        }

        protected bool OnValidateCertificate(X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            FtpSocketStreamSslValidation sslvalidate = this.m_sslvalidate;
            if (sslvalidate != null)
            {
                FtpSslValidationEventArgs e = new FtpSslValidationEventArgs {
                    Certificate = certificate,
                    Chain = chain,
                    PolicyErrors = errors,
                    Accept = errors == SslPolicyErrors.None
                };
                sslvalidate(this, e);
                return e.Accept;
            }
            return (errors == SslPolicyErrors.None);
        }

        internal int RawSocketRead(byte[] buffer)
        {
            int num = 0;
            if ((this.m_socket != null) && this.m_socket.Connected)
            {
                num = this.m_socket.Receive(buffer, buffer.Length, SocketFlags.None);
            }
            return num;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            IAsyncResult asyncResult = null;
            if (this.BaseStream == null)
            {
                return 0;
            }
            this.m_lastActivity = DateTime.Now;
            asyncResult = this.BaseStream.BeginRead(buffer, offset, count, null, null);
            if (!asyncResult.AsyncWaitHandle.WaitOne(this.m_readTimeout, true))
            {
                this.Close();
                throw new TimeoutException("Timed out trying to read data from the socket stream!");
            }
            return this.BaseStream.EndRead(asyncResult);
        }

        public string ReadLine(Encoding encoding)
        {
            List<byte> list = new List<byte>();
            byte[] buffer = new byte[1];
            while (this.Read(buffer, 0, buffer.Length) > 0)
            {
                list.Add(buffer[0]);
                if (buffer[0] == 10)
                {
                    return encoding.GetString(list.ToArray()).Trim(new char[] { '\r', '\n' });
                }
            }
            return null;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new InvalidOperationException();
        }

        public override void SetLength(long value)
        {
            throw new InvalidOperationException();
        }

        public void SetSocketOption(SocketOptionLevel level, SocketOptionName name, bool value)
        {
            if (this.m_socket == null)
            {
                throw new InvalidOperationException("The underlying socket is null. Have you established a connection?");
            }
            this.m_socket.SetSocketOption(level, name, value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (this.BaseStream != null)
            {
                this.BaseStream.Write(buffer, offset, count);
                this.m_lastActivity = DateTime.Now;
            }
        }

        public void WriteLine(Encoding encoding, string buf)
        {
            byte[] bytes = encoding.GetBytes(string.Format("{0}\r\n", buf));
            this.Write(bytes, 0, bytes.Length);
        }

        protected Stream BaseStream
        {
            get
            {
                if (this.m_sslStream != null)
                {
                    return this.m_sslStream;
                }
                if (this.m_netStream != null)
                {
                    return this.m_netStream;
                }
                return null;
            }
        }

        public override bool CanRead
        {
            get
            {
                return ((this.m_netStream != null) && this.m_netStream.CanRead);
            }
        }

        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        public override bool CanWrite
        {
            get
            {
                return ((this.m_netStream != null) && this.m_netStream.CanWrite);
            }
        }

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

        public bool IsConnected
        {
            get
            {
                try
                {
                    if (this.m_socket == null)
                    {
                        return false;
                    }
                    if (!this.m_socket.Connected)
                    {
                        this.Close();
                        return false;
                    }
                    if (!this.CanRead || !this.CanWrite)
                    {
                        this.Close();
                        return false;
                    }
                    if ((this.m_socketPollInterval > 0) && (DateTime.Now.Subtract(this.m_lastActivity).TotalMilliseconds > this.m_socketPollInterval))
                    {
                        FtpTrace.WriteLine("Testing connectivity using Socket.Poll()...");
                        if (this.m_socket.Poll(0x7a120, SelectMode.SelectRead) && (this.m_socket.Available == 0))
                        {
                            this.Close();
                            return false;
                        }
                    }
                }
                catch (SocketException exception)
                {
                    this.Close();
                    FtpTrace.WriteLine("FtpSocketStream.IsConnected: Caught and discarded SocketException while testing for connectivity: {0}", new object[] { exception.ToString() });
                    return false;
                }
                catch (IOException exception2)
                {
                    this.Close();
                    FtpTrace.WriteLine("FtpSocketStream.IsConnected: Caught and discarded IOException while testing for connectivity: {0}", new object[] { exception2.ToString() });
                    return false;
                }
                return true;
            }
        }

        public bool IsEncrypted
        {
            get
            {
                return (this.m_sslStream != null);
            }
        }

        public override long Length
        {
            get
            {
                return 0L;
            }
        }

        public IPEndPoint LocalEndPoint
        {
            get
            {
                if (this.m_socket == null)
                {
                    return null;
                }
                return (IPEndPoint) this.m_socket.LocalEndPoint;
            }
        }

        private System.Net.Sockets.NetworkStream NetworkStream
        {
            get
            {
                return this.m_netStream;
            }
            set
            {
                this.m_netStream = value;
            }
        }

        public override long Position
        {
            get
            {
                if (this.BaseStream != null)
                {
                    return this.BaseStream.Position;
                }
                return 0L;
            }
            set
            {
                throw new InvalidOperationException();
            }
        }

        public override int ReadTimeout
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

        public IPEndPoint RemoteEndPoint
        {
            get
            {
                if (this.m_socket == null)
                {
                    return null;
                }
                return (IPEndPoint) this.m_socket.RemoteEndPoint;
            }
        }

        protected System.Net.Sockets.Socket Socket
        {
            get
            {
                return this.m_socket;
            }
            private set
            {
                this.m_socket = value;
            }
        }

        internal int SocketDataAvailable
        {
            get
            {
                if (this.m_socket != null)
                {
                    return this.m_socket.Available;
                }
                return 0;
            }
        }

        public int SocketPollInterval
        {
            get
            {
                return this.m_socketPollInterval;
            }
            set
            {
                this.m_socketPollInterval = value;
            }
        }

        private System.Net.Security.SslStream SslStream
        {
            get
            {
                return this.m_sslStream;
            }
            set
            {
                this.m_sslStream = value;
            }
        }
    }
}

