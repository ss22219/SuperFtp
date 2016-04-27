namespace System.Net.FtpClient
{
    using System;

    public interface IFtpReply
    {
        string Code { get; set; }

        string ErrorMessage { get; }

        string InfoMessages { get; set; }

        string Message { get; set; }

        bool Success { get; }

        FtpResponseType Type { get; }
    }
}

