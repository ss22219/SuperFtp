namespace System.Net.FtpClient
{
    using System;

    public interface IFtpListItem
    {
        string ToString();

        DateTime Created { get; set; }

        string FullName { get; set; }

        FtpPermission GroupPermissions { get; set; }

        string Input { get; }

        FtpListItem LinkObject { get; set; }

        string LinkTarget { get; set; }

        DateTime Modified { get; set; }

        string Name { get; set; }

        FtpPermission OthersPermissions { get; set; }

        FtpPermission OwnerPermissions { get; set; }

        long Size { get; set; }

        FtpSpecialPermissions SpecialPermissions { get; set; }

        FtpFileSystemObjectType Type { get; set; }
    }
}

