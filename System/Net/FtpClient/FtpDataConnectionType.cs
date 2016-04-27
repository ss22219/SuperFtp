namespace System.Net.FtpClient
{
    using System;

    public enum FtpDataConnectionType
    {
        AutoPassive,
        PASV,
        PASVEX,
        EPSV,
        AutoActive,
        PORT,
        EPRT
    }
}

