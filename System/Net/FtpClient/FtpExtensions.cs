namespace System.Net.FtpClient
{
    using System;
    using System.Globalization;
    using System.Runtime.CompilerServices;
    using System.Text.RegularExpressions;

    public static class FtpExtensions
    {
        public static DateTime GetFtpDate(this string date, DateTimeStyles style)
        {
            DateTime time;
            string[] formats = new string[] { "yyyyMMddHHmmss", "yyyyMMddHHmmss.fff", "MMM dd  yyyy", "MMM  d  yyyy", "MMM dd HH:mm", "MMM  d HH:mm" };
            if (DateTime.TryParseExact(date, formats, CultureInfo.InvariantCulture, style, out time))
            {
                return time;
            }
            return DateTime.MinValue;
        }

        public static string GetFtpDirectoryName(this string path)
        {
            string str = (path == null) ? "" : path.GetFtpPath();
            int length = -1;
            if ((str.Length == 0) || (str == "/"))
            {
                return "/";
            }
            length = str.LastIndexOf('/');
            if (length < 0)
            {
                return ".";
            }
            return str.Substring(0, length);
        }

        public static string GetFtpFileName(this string path)
        {
            string str = (path == null) ? null : path;
            int startIndex = -1;
            if (str == null)
            {
                return null;
            }
            startIndex = str.LastIndexOf('/');
            if (startIndex < 0)
            {
                return str;
            }
            startIndex++;
            if (startIndex >= str.Length)
            {
                return str;
            }
            return str.Substring(startIndex, str.Length - startIndex);
        }

        public static string GetFtpPath(this string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return "./";
            }
            path = Regex.Replace(path.Replace('\\', '/'), "[/]+", "/").TrimEnd(new char[] { '/' });
            if (path.Length == 0)
            {
                path = "/";
            }
            return path;
        }

        public static string GetFtpPath(this string path, params string[] segments)
        {
            if (string.IsNullOrEmpty(path))
            {
                path = "./";
            }
            foreach (string str in segments)
            {
                if (str != null)
                {
                    if ((path.Length > 0) && !path.EndsWith("/"))
                    {
                        path = path + "/";
                    }
                    path = path + Regex.Replace(str.Replace('\\', '/'), "[/]+", "/").TrimEnd(new char[] { '/' });
                }
            }
            path = Regex.Replace(path.Replace('\\', '/'), "[/]+", "/").TrimEnd(new char[] { '/' });
            if (path.Length == 0)
            {
                path = "/";
            }
            return path;
        }
    }
}

