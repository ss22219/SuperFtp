namespace System.Net.FtpClient
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    public class FtpHash
    {
        private FtpHashAlgorithm m_algorithm;
        private string m_value;

        internal FtpHash()
        {
        }

        public bool Verify(Stream istream)
        {
            if (this.IsValid)
            {
                HashAlgorithm algorithm = null;
                switch (this.m_algorithm)
                {
                    case FtpHashAlgorithm.SHA1:
                        algorithm = new SHA1CryptoServiceProvider();
                        break;

                    case FtpHashAlgorithm.SHA256:
                        algorithm = new SHA256CryptoServiceProvider();
                        break;

                    case FtpHashAlgorithm.SHA512:
                        algorithm = new SHA512CryptoServiceProvider();
                        break;

                    case FtpHashAlgorithm.MD5:
                        algorithm = new MD5CryptoServiceProvider();
                        break;

                    case FtpHashAlgorithm.CRC:
                        throw new NotImplementedException("There is no built in support for computing CRC hashes.");

                    default:
                        throw new NotImplementedException("Unknown hash algorithm: " + this.m_algorithm.ToString());
                }
                try
                {
                    byte[] buffer = null;
                    string str = "";
                    buffer = algorithm.ComputeHash(istream);
                    if (buffer != null)
                    {
                        foreach (byte num in buffer)
                        {
                            str = str + num.ToString("x2");
                        }
                        return (str.ToUpper() == this.m_value.ToUpper());
                    }
                }
                finally
                {
                    if (algorithm != null)
                    {
                        algorithm.Dispose();
                    }
                }
            }
            return false;
        }

        public bool Verify(string file)
        {
            using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.Read))
            {
                return this.Verify(stream);
            }
        }

        public FtpHashAlgorithm Algorithm
        {
            get
            {
                return this.m_algorithm;
            }
            internal set
            {
                this.m_algorithm = value;
            }
        }

        public bool IsValid
        {
            get
            {
                return ((this.m_algorithm != FtpHashAlgorithm.NONE) && !string.IsNullOrEmpty(this.m_value));
            }
        }

        public string Value
        {
            get
            {
                return this.m_value;
            }
            internal set
            {
                this.m_value = value;
            }
        }
    }
}

