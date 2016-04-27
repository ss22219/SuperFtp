namespace System.Net.FtpClient
{
    using System;
    using System.Runtime.InteropServices;
    using System.Text.RegularExpressions;

    [StructLayout(LayoutKind.Sequential)]
    public struct FtpReply : IFtpReply
    {
        private string m_respCode;
        private string m_respMessage;
        private string m_infoMessages;
        public FtpResponseType Type
        {
            get
            {
                if ((this.Code != null) && (this.Code.Length > 0))
                {
                    int num;
                    char ch = this.Code[0];
                    if (int.TryParse(ch.ToString(), out num))
                    {
                        return (FtpResponseType) num;
                    }
                }
                return FtpResponseType.None;
            }
        }
        public string Code
        {
            get
            {
                return this.m_respCode;
            }
            set
            {
                this.m_respCode = value;
            }
        }
        public string Message
        {
            get
            {
                return this.m_respMessage;
            }
            set
            {
                this.m_respMessage = value;
            }
        }
        public string InfoMessages
        {
            get
            {
                return this.m_infoMessages;
            }
            set
            {
                this.m_infoMessages = value;
            }
        }
        public bool Success
        {
            get
            {
                if ((this.Code != null) && (this.Code.Length > 0))
                {
                    int num;
                    char ch = this.Code[0];
                    if ((int.TryParse(ch.ToString(), out num) && (num >= 1)) && (num <= 3))
                    {
                        return true;
                    }
                }
                return false;
            }
        }
        public string ErrorMessage
        {
            get
            {
                string str = "";
                if (this.Success)
                {
                    return str;
                }
                if ((this.InfoMessages != null) && (this.InfoMessages.Length > 0))
                {
                    foreach (string str2 in this.InfoMessages.Split(new char[] { '\n' }))
                    {
                        string str3 = Regex.Replace(str2, "^[0-9]{3}-", "");
                        str = str + string.Format("{0}; ", str3.Trim());
                    }
                }
                return (str + this.Message);
            }
        }
    }
}

