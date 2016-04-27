namespace System.Net.FtpClient
{
    using System;

    public enum FtpResponseType
    {
        None,
        PositivePreliminary,
        PositiveCompletion,
        PositiveIntermediate,
        TransientNegativeCompletion,
        PermanentNegativeCompletion
    }
}

