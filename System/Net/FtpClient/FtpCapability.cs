namespace System.Net.FtpClient
{
    using System;

    [Flags]
    public enum FtpCapability
    {
        HASH = 0x400,
        MD5 = 0x800,
        MDTM = 4,
        MFCT = 0x80,
        MFF = 0x100,
        MFMT = 0x40,
        MLSD = 1,
        NONE = 0,
        PRET = 0x20,
        REST = 8,
        SIZE = 2,
        STAT = 0x200,
        UTF8 = 0x10,
        XCRC = 0x2000,
        XMD5 = 0x1000,
        XSHA1 = 0x4000,
        XSHA256 = 0x8000,
        XSHA512 = 0x10000
    }
}

