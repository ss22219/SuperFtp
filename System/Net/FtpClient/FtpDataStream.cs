namespace System.Net.FtpClient
{
    using System;

    public class FtpDataStream : FtpSocketStream
    {
        private FtpReply m_commandStatus;
        private System.Net.FtpClient.FtpClient m_control;
        private long m_length;
        private long m_position;

        public FtpDataStream(System.Net.FtpClient.FtpClient conn)
        {
            if (conn == null)
            {
                throw new ArgumentException("The control connection cannot be null.");
            }
            this.ControlConnection = conn;
            base.ValidateCertificate += (obj, e) => e.Accept = true;
            this.m_position = 0L;
        }

        public FtpReply Close()
        {
            base.Close();
            try
            {
                if (this.ControlConnection != null)
                {
                    return this.ControlConnection.CloseDataStream(this);
                }
            }
            finally
            {
                this.m_commandStatus = new FtpReply();
                this.m_control = null;
            }
            return new FtpReply();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (base.IsConnected)
                {
                    this.Close();
                }
                this.m_control = null;
            }
            base.Dispose(disposing);
        }

        ~FtpDataStream()
        {
            try
            {
                base.Dispose();
            }
            catch (Exception exception)
            {
                FtpTrace.WriteLine("[Finalizer] Caught and discarded an exception while disposing the FtpDataStream: {0}", new object[] { exception.ToString() });
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int num = base.Read(buffer, offset, count);
            this.m_position += num;
            return num;
        }

        public override void SetLength(long value)
        {
            this.m_length = value;
        }

        public void SetPosition(long pos)
        {
            this.m_position = pos;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            base.Write(buffer, offset, count);
            this.m_position += count;
        }

        public FtpReply CommandStatus
        {
            get
            {
                return this.m_commandStatus;
            }
            set
            {
                this.m_commandStatus = value;
            }
        }

        public System.Net.FtpClient.FtpClient ControlConnection
        {
            get
            {
                return this.m_control;
            }
            set
            {
                this.m_control = value;
            }
        }

        public override long Length
        {
            get
            {
                return this.m_length;
            }
        }

        public override long Position
        {
            get
            {
                return this.m_position;
            }
            set
            {
                throw new InvalidOperationException("You cannot modify the position of a FtpDataStream. This property is updated as data is read or written to the stream.");
            }
        }
    }
}

