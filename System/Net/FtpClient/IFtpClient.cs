namespace System.Net.FtpClient
{
    using System;
    using System.IO;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;

    public interface IFtpClient : IDisposable
    {
        event FtpSslValidation ValidateCertificate;

        IAsyncResult BeginConnect(AsyncCallback callback, object state);
        IAsyncResult BeginCreateDirectory(string path, AsyncCallback callback, object state);
        IAsyncResult BeginCreateDirectory(string path, bool force, AsyncCallback callback, object state);
        IAsyncResult BeginDeleteDirectory(string path, AsyncCallback callback, object state);
        IAsyncResult BeginDeleteDirectory(string path, bool force, AsyncCallback callback, object state);
        IAsyncResult BeginDeleteDirectory(string path, bool force, FtpListOption options, AsyncCallback callback, object state);
        IAsyncResult BeginDeleteFile(string path, AsyncCallback callback, object state);
        IAsyncResult BeginDereferenceLink(FtpListItem item, AsyncCallback callback, object state);
        IAsyncResult BeginDereferenceLink(FtpListItem item, int recMax, AsyncCallback callback, object state);
        IAsyncResult BeginDirectoryExists(string path, AsyncCallback callback, object state);
        IAsyncResult BeginDisconnect(AsyncCallback callback, object state);
        IAsyncResult BeginExecute(string command, AsyncCallback callback, object state);
        IAsyncResult BeginFileExists(string path, AsyncCallback callback, object state);
        IAsyncResult BeginFileExists(string path, FtpListOption options, AsyncCallback callback, object state);
        IAsyncResult BeginGetFileSize(string path, AsyncCallback callback, object state);
        IAsyncResult BeginGetHash(string path, AsyncCallback callback, object state);
        IAsyncResult BeginGetHashAlgorithm(AsyncCallback callback, object state);
        IAsyncResult BeginGetListing(AsyncCallback callback, object state);
        IAsyncResult BeginGetListing(string path, AsyncCallback callback, object state);
        IAsyncResult BeginGetListing(string path, FtpListOption options, AsyncCallback callback, object state);
        IAsyncResult BeginGetModifiedTime(string path, AsyncCallback callback, object state);
        IAsyncResult BeginGetNameListing(AsyncCallback callback, object state);
        IAsyncResult BeginGetNameListing(string path, AsyncCallback callback, object state);
        IAsyncResult BeginGetObjectInfo(string path, AsyncCallback callback, object state);
        IAsyncResult BeginGetWorkingDirectory(AsyncCallback callback, object state);
        IAsyncResult BeginOpenAppend(string path, AsyncCallback callback, object state);
        IAsyncResult BeginOpenAppend(string path, FtpDataType type, AsyncCallback callback, object state);
        IAsyncResult BeginOpenRead(string path, AsyncCallback callback, object state);
        IAsyncResult BeginOpenRead(string path, long restart, AsyncCallback callback, object state);
        IAsyncResult BeginOpenRead(string path, FtpDataType type, AsyncCallback callback, object state);
        IAsyncResult BeginOpenRead(string path, FtpDataType type, long restart, AsyncCallback callback, object state);
        IAsyncResult BeginOpenWrite(string path, AsyncCallback callback, object state);
        IAsyncResult BeginOpenWrite(string path, FtpDataType type, AsyncCallback callback, object state);
        IAsyncResult BeginRename(string path, string dest, AsyncCallback callback, object state);
        IAsyncResult BeginSetHashAlgorithm(FtpHashAlgorithm type, AsyncCallback callback, object state);
        IAsyncResult BeginSetWorkingDirectory(string path, AsyncCallback callback, object state);
        void Connect();
        void CreateDirectory(string path);
        void CreateDirectory(string path, bool force);
        void DeleteDirectory(string path);
        void DeleteDirectory(string path, bool force);
        void DeleteDirectory(string path, bool force, FtpListOption options);
        void DeleteFile(string path);
        FtpListItem DereferenceLink(FtpListItem item);
        FtpListItem DereferenceLink(FtpListItem item, int recMax);
        bool DirectoryExists(string path);
        void DisableUTF8();
        void Disconnect();
        void EndConnect(IAsyncResult ar);
        void EndCreateDirectory(IAsyncResult ar);
        void EndDeleteDirectory(IAsyncResult ar);
        void EndDeleteFile(IAsyncResult ar);
        FtpListItem EndDereferenceLink(IAsyncResult ar);
        bool EndDirectoryExists(IAsyncResult ar);
        void EndDisconnect(IAsyncResult ar);
        FtpReply EndExecute(IAsyncResult ar);
        bool EndFileExists(IAsyncResult ar);
        long EndGetFileSize(IAsyncResult ar);
        void EndGetHash(IAsyncResult ar);
        FtpHashAlgorithm EndGetHashAlgorithm(IAsyncResult ar);
        FtpListItem[] EndGetListing(IAsyncResult ar);
        DateTime EndGetModifiedTime(IAsyncResult ar);
        string[] EndGetNameListing(IAsyncResult ar);
        FtpListItem EndGetObjectInfo(IAsyncResult ar);
        string EndGetWorkingDirectory(IAsyncResult ar);
        Stream EndOpenAppend(IAsyncResult ar);
        Stream EndOpenRead(IAsyncResult ar);
        Stream EndOpenWrite(IAsyncResult ar);
        void EndRename(IAsyncResult ar);
        void EndSetHashAlgorithm(IAsyncResult ar);
        void EndSetWorkingDirectory(IAsyncResult ar);
        FtpReply Execute(string command);
        FtpReply Execute(string command, params object[] args);
        bool FileExists(string path);
        bool FileExists(string path, FtpListOption options);
        long GetFileSize(string path);
        FtpHash GetHash(string path);
        FtpHashAlgorithm GetHashAlgorithm();
        FtpListItem[] GetListing();
        FtpListItem[] GetListing(string path);
        FtpListItem[] GetListing(string path, FtpListOption options);
        DateTime GetModifiedTime(string path);
        string[] GetNameListing();
        string[] GetNameListing(string path);
        FtpListItem GetObjectInfo(string path);
        string GetWorkingDirectory();
        bool HasFeature(FtpCapability cap);
        Stream OpenAppend(string path);
        Stream OpenAppend(string path, FtpDataType type);
        Stream OpenRead(string path);
        Stream OpenRead(string path, long restart);
        Stream OpenRead(string path, FtpDataType type);
        Stream OpenRead(string path, FtpDataType type, long restart);
        Stream OpenWrite(string path);
        Stream OpenWrite(string path, FtpDataType type);
        void Rename(string path, string dest);
        void SetHashAlgorithm(FtpHashAlgorithm type);
        void SetWorkingDirectory(string path);

        FtpCapability Capabilities { get; }

        X509CertificateCollection ClientCertificates { get; }

        int ConnectTimeout { get; set; }

        NetworkCredential Credentials { get; set; }

        int DataConnectionConnectTimeout { get; set; }

        bool DataConnectionEncryption { get; set; }

        int DataConnectionReadTimeout { get; set; }

        FtpDataConnectionType DataConnectionType { get; set; }

        bool EnableThreadSafeDataConnections { get; set; }

        System.Text.Encoding Encoding { get; set; }

        FtpEncryptionMode EncryptionMode { get; set; }

        FtpHashAlgorithm HashAlgorithms { get; }

        string Host { get; set; }

        FtpIpVersion InternetProtocolVersions { get; set; }

        bool IsConnected { get; }

        bool IsDisposed { get; }

        int MaximumDereferenceCount { get; set; }

        int Port { get; set; }

        int ReadTimeout { get; set; }

        bool SocketKeepAlive { get; set; }

        int SocketPollInterval { get; set; }

        bool StaleDataCheck { get; set; }

        string SystemType { get; }

        bool UngracefullDisconnection { get; set; }
    }
}

