namespace System.Net.FtpClient
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Reflection;
    using System.Runtime.CompilerServices;
    using System.Text;
    using System.Text.RegularExpressions;

    public class FtpListItem : IFtpListItem
    {
        private DateTime m_created = DateTime.MinValue;
        private FtpPermission m_groupPermissions;
        private string m_input;
        private FtpListItem m_linkObject;
        private string m_linkTarget;
        private DateTime m_modified = DateTime.MinValue;
        private string m_name;
        private FtpPermission m_otherPermissions;
        private FtpPermission m_ownerPermissions;
        private static object m_parserLock = new object();
        private static List<Parser> m_parsers = null;
        private string m_path;
        private long m_size = -1L;
        private FtpSpecialPermissions m_specialPermissions;
        private FtpFileSystemObjectType m_type;

        public static void AddParser(Parser parser)
        {
            lock (m_parserLock)
            {
                if (m_parsers == null)
                {
                    InitParsers();
                }
                m_parsers.Add(parser);
            }
        }

        public static void ClearParsers()
        {
            lock (m_parserLock)
            {
                if (m_parsers == null)
                {
                    InitParsers();
                }
                m_parsers.Clear();
            }
        }

        private static void InitParsers()
        {
            lock (m_parserLock)
            {
                if (m_parsers == null)
                {
                    m_parsers = new List<Parser>();
                    m_parsers.Add(new Parser(FtpListItem.ParseMachineList));
                    m_parsers.Add(new Parser(FtpListItem.ParseUnixList));
                    m_parsers.Add(new Parser(FtpListItem.ParseDosList));
                    m_parsers.Add(new Parser(FtpListItem.ParseVaxList));
                }
            }
        }

        public static FtpListItem Parse(string path, string buf, FtpCapability capabilities)
        {
            if ((buf != null) && (buf.Length > 0))
            {
                foreach (Parser parser in Parsers)
                {
                    FtpListItem item = parser(buf, capabilities);
                    if (item != null)
                    {
                        if (parser == new Parser(FtpListItem.ParseVaxList))
                        {
                            item.FullName = path + item.Name;
                        }
                        else
                        {
                            FtpTrace.WriteLine(item.Name);
                            if (path.GetFtpFileName().Contains("*"))
                            {
                                path = path.GetFtpDirectoryName();
                            }
                            if (item.Name != null)
                            {
                                if ((item.Name.StartsWith("/") || item.Name.StartsWith("./")) || item.Name.StartsWith("../"))
                                {
                                    item.FullName = item.Name;
                                    item.Name = item.Name.GetFtpFileName();
                                }
                                else if (path != null)
                                {
                                    item.FullName = path.GetFtpPath(new string[] { item.Name });
                                }
                                else
                                {
                                    FtpTrace.WriteLine("Couldn't determine the full path of this object:{0}{1}", new object[] { Environment.NewLine, item.ToString() });
                                }
                            }
                            if ((item.LinkTarget != null) && !item.LinkTarget.StartsWith("/"))
                            {
                                if (item.LinkTarget.StartsWith("./"))
                                {
                                    item.LinkTarget = path.GetFtpPath(new string[] { item.LinkTarget.Remove(0, 2) });
                                }
                                else
                                {
                                    item.LinkTarget = path.GetFtpPath(new string[] { item.LinkTarget });
                                }
                            }
                        }
                        item.Input = buf;
                        return item;
                    }
                }
            }
            return null;
        }

        private static FtpListItem ParseDosList(string buf, FtpCapability capabilities)
        {
            Match match;
            DateTime time2;
            long num;
            FtpListItem item = new FtpListItem();
            string[] formats = new string[] { "MM-dd-yy  hh:mmtt", "MM-dd-yyyy  hh:mmtt" };
            if ((match = Regex.Match(buf, @"(?<modify>\d+-\d+-\d+\s+\d+:\d+\w+)\s+<DIR>\s+(?<name>.*)$", RegexOptions.IgnoreCase)).Success)
            {
                DateTime time;
                item.Type = FtpFileSystemObjectType.Directory;
                item.Name = match.Groups["name"].Value;
                if (DateTime.TryParseExact(match.Groups["modify"].Value, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out time))
                {
                    item.Modified = time;
                }
                return item;
            }
            if (!(match = Regex.Match(buf, @"(?<modify>\d+-\d+-\d+\s+\d+:\d+\w+)\s+(?<size>\d+)\s+(?<name>.*)$", RegexOptions.IgnoreCase)).Success)
            {
                return null;
            }
            item.Type = FtpFileSystemObjectType.File;
            item.Name = match.Groups["name"].Value;
            if (long.TryParse(match.Groups["size"].Value, out num))
            {
                item.Size = num;
            }
            if (DateTime.TryParseExact(match.Groups["modify"].Value, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out time2))
            {
                item.Modified = time2;
            }
            return item;
        }

        private static FtpListItem ParseMachineList(string buf, FtpCapability capabilities)
        {
            Match match;
            long num;
            FtpListItem item = new FtpListItem();
            if ((match = Regex.Match(buf, "type=(?<type>.+?);", RegexOptions.IgnoreCase)).Success)
            {
                switch (match.Groups["type"].Value.ToLower())
                {
                    case "dir":
                    case "pdir":
                    case "cdir":
                        item.Type = FtpFileSystemObjectType.Directory;
                        goto Label_00E2;

                    case "file":
                        item.Type = FtpFileSystemObjectType.File;
                        goto Label_00E2;
                }
            }
            return null;
        Label_00E2:
            if ((match = Regex.Match(buf, "; (?<name>.*)$", RegexOptions.IgnoreCase)).Success)
            {
                item.Name = match.Groups["name"].Value;
            }
            else
            {
                return null;
            }
            if ((match = Regex.Match(buf, "modify=(?<modify>.+?);", RegexOptions.IgnoreCase)).Success)
            {
                item.Modified = match.Groups["modify"].Value.GetFtpDate(DateTimeStyles.AssumeUniversal);
            }
            if ((match = Regex.Match(buf, "created?=(?<create>.+?);", RegexOptions.IgnoreCase)).Success)
            {
                item.Created = match.Groups["create"].Value.GetFtpDate(DateTimeStyles.AssumeUniversal);
            }
            if ((match = Regex.Match(buf, @"size=(?<size>\d+);", RegexOptions.IgnoreCase)).Success && long.TryParse(match.Groups["size"].Value, out num))
            {
                item.Size = num;
            }
            if ((match = Regex.Match(buf, @"unix.mode=(?<mode>\d+);", RegexOptions.IgnoreCase)).Success)
            {
                if (match.Groups["mode"].Value.Length == 4)
                {
                    char ch = match.Groups["mode"].Value[0];
                    item.SpecialPermissions = (FtpSpecialPermissions) int.Parse(ch.ToString());
                    char ch2 = match.Groups["mode"].Value[1];
                    item.OwnerPermissions = (FtpPermission) int.Parse(ch2.ToString());
                    char ch3 = match.Groups["mode"].Value[2];
                    item.GroupPermissions = (FtpPermission) int.Parse(ch3.ToString());
                    char ch4 = match.Groups["mode"].Value[3];
                    item.OthersPermissions = (FtpPermission) int.Parse(ch4.ToString());
                    return item;
                }
                if (match.Groups["mode"].Value.Length == 3)
                {
                    char ch5 = match.Groups["mode"].Value[0];
                    item.OwnerPermissions = (FtpPermission) int.Parse(ch5.ToString());
                    char ch6 = match.Groups["mode"].Value[1];
                    item.GroupPermissions = (FtpPermission) int.Parse(ch6.ToString());
                    char ch7 = match.Groups["mode"].Value[2];
                    item.OthersPermissions = (FtpPermission) int.Parse(ch7.ToString());
                }
            }
            return item;
        }

        private static FtpListItem ParseUnixList(string buf, FtpCapability capabilities)
        {
            Match match;
            long num;
            string pattern = @"(?<permissions>.+)\s+(?<objectcount>\d+)\s+(?<user>.+)\s+(?<group>.+)\s+(?<size>\d+)\s+(?<modify>\w+\s+\d+\s+\d+:\d+|\w+\s+\d+\s+\d+)\s(?<name>.*)$";
            FtpListItem item = new FtpListItem();
            if ((match = Regex.Match(buf, pattern, RegexOptions.IgnoreCase)).Success)
            {
                if (match.Groups["permissions"].Value.Length == 0)
                {
                    return null;
                }
                switch (match.Groups["permissions"].Value[0])
                {
                    case 'l':
                        item.Type = FtpFileSystemObjectType.Link;
                        goto Label_0099;

                    case 's':
                    case '-':
                        item.Type = FtpFileSystemObjectType.File;
                        goto Label_0099;

                    case 'd':
                        item.Type = FtpFileSystemObjectType.Directory;
                        goto Label_0099;
                }
            }
            return null;
        Label_0099:
            if (match.Groups["name"].Value.Length < 1)
            {
                return null;
            }
            item.Name = match.Groups["name"].Value;
            switch (item.Type)
            {
                case FtpFileSystemObjectType.Directory:
                    if (!(item.Name == ".") && !(item.Name == ".."))
                    {
                        break;
                    }
                    return null;

                case FtpFileSystemObjectType.Link:
                    if (item.Name.Contains(" -> "))
                    {
                        item.LinkTarget = item.Name.Remove(0, item.Name.IndexOf("-> ") + 3);
                        item.Name = item.Name.Remove(item.Name.IndexOf(" -> "));
                        break;
                    }
                    return null;
            }
            if ((((capabilities & FtpCapability.MDTM) != FtpCapability.MDTM) || (item.Type == FtpFileSystemObjectType.Directory)) && (match.Groups["modify"].Value.Length > 0))
            {
                item.Modified = match.Groups["modify"].Value.GetFtpDate(DateTimeStyles.AssumeLocal);
                if (item.Modified == DateTime.MinValue)
                {
                    FtpTrace.WriteLine("GetFtpDate() failed on {0}", new object[] { match.Groups["modify"].Value });
                }
            }
            else if (match.Groups["modify"].Value.Length == 0)
            {
                FtpTrace.WriteLine("RegEx failed to parse modified date from {0}.", new object[] { buf });
            }
            else if (item.Type == FtpFileSystemObjectType.Directory)
            {
                FtpTrace.WriteLine("Modified times of directories are ignored in UNIX long listings.");
            }
            else if ((capabilities & FtpCapability.MDTM) == FtpCapability.MDTM)
            {
                FtpTrace.WriteLine("Ignoring modified date because MDTM feature is present. If you aren't already, pass FtpListOption.Modify or FtpListOption.SizeModify to GetListing() to retrieve the modification time.");
            }
            if ((match.Groups["size"].Value.Length > 0) && long.TryParse(match.Groups["size"].Value, out num))
            {
                item.Size = num;
            }
            if (match.Groups["permissions"].Value.Length > 0)
            {
                Match match2 = Regex.Match(match.Groups["permissions"].Value, @"[\w-]{1}(?<owner>[\w-]{3})(?<group>[\w-]{3})(?<others>[\w-]{3})", RegexOptions.IgnoreCase);
                if (!match2.Success)
                {
                    return item;
                }
                if (match2.Groups["owner"].Value.Length == 3)
                {
                    if (match2.Groups["owner"].Value[0] == 'r')
                    {
                        item.OwnerPermissions |= FtpPermission.None | FtpPermission.Read;
                    }
                    if (match2.Groups["owner"].Value[1] == 'w')
                    {
                        item.OwnerPermissions |= FtpPermission.None | FtpPermission.Write;
                    }
                    if ((match2.Groups["owner"].Value[2] == 'x') || (match2.Groups["owner"].Value[2] == 's'))
                    {
                        item.OwnerPermissions |= FtpPermission.Execute;
                    }
                    if ((match2.Groups["owner"].Value[2] == 's') || (match2.Groups["owner"].Value[2] == 'S'))
                    {
                        item.SpecialPermissions |= FtpSpecialPermissions.SetUserID;
                    }
                }
                if (match2.Groups["group"].Value.Length == 3)
                {
                    if (match2.Groups["group"].Value[0] == 'r')
                    {
                        item.GroupPermissions |= FtpPermission.None | FtpPermission.Read;
                    }
                    if (match2.Groups["group"].Value[1] == 'w')
                    {
                        item.GroupPermissions |= FtpPermission.None | FtpPermission.Write;
                    }
                    if ((match2.Groups["group"].Value[2] == 'x') || (match2.Groups["group"].Value[2] == 's'))
                    {
                        item.GroupPermissions |= FtpPermission.Execute;
                    }
                    if ((match2.Groups["group"].Value[2] == 's') || (match2.Groups["group"].Value[2] == 'S'))
                    {
                        item.SpecialPermissions |= FtpSpecialPermissions.SetGroupID;
                    }
                }
                if (match2.Groups["others"].Value.Length == 3)
                {
                    if (match2.Groups["others"].Value[0] == 'r')
                    {
                        item.OthersPermissions |= FtpPermission.None | FtpPermission.Read;
                    }
                    if (match2.Groups["others"].Value[1] == 'w')
                    {
                        item.OthersPermissions |= FtpPermission.None | FtpPermission.Write;
                    }
                    if ((match2.Groups["others"].Value[2] == 'x') || (match2.Groups["others"].Value[2] == 't'))
                    {
                        item.OthersPermissions |= FtpPermission.Execute;
                    }
                    if ((match2.Groups["others"].Value[2] != 't') && (match2.Groups["others"].Value[2] != 'T'))
                    {
                        return item;
                    }
                    item.SpecialPermissions |= FtpSpecialPermissions.Sticky;
                }
            }
            return item;
        }

        private static FtpListItem ParseVaxList(string buf, FtpCapability capabilities)
        {
            Match match;
            string pattern = @"(?<name>.+)\.(?<extension>.+);(?<version>\d+)\s+(?<size>\d+)\s+(?<modify>\d+-\w+-\d+\s+\d+:\d+)";
            if (!(match = Regex.Match(buf, pattern)).Success)
            {
                return null;
            }
            FtpListItem item = new FtpListItem {
                m_name = string.Format("{0}.{1};{2}", match.Groups["name"].Value, match.Groups["extension"].Value, match.Groups["version"].Value)
            };
            if (match.Groups["extension"].Value.ToUpper() == "DIR")
            {
                item.m_type = FtpFileSystemObjectType.Directory;
            }
            else
            {
                item.m_type = FtpFileSystemObjectType.File;
            }
            if (!long.TryParse(match.Groups["size"].Value, out item.m_size))
            {
                item.m_size = -1L;
            }
            if (!DateTime.TryParse(match.Groups["modify"].Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out item.m_modified))
            {
                item.m_modified = DateTime.MinValue;
            }
            return item;
        }

        public static void RemoveParser(Parser parser)
        {
            lock (m_parserLock)
            {
                if (m_parsers == null)
                {
                    InitParsers();
                }
                m_parsers.Remove(parser);
            }
        }

        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            foreach (PropertyInfo info in base.GetType().GetProperties())
            {
                builder.AppendLine(string.Format("{0}: {1}", info.Name, info.GetValue(this, null)));
            }
            return builder.ToString();
        }

        public DateTime Created
        {
            get
            {
                return this.m_created;
            }
            set
            {
                this.m_created = value;
            }
        }

        public string FullName
        {
            get
            {
                return this.m_path;
            }
            set
            {
                this.m_path = value;
            }
        }

        public FtpPermission GroupPermissions
        {
            get
            {
                return this.m_groupPermissions;
            }
            set
            {
                this.m_groupPermissions = value;
            }
        }

        public string Input
        {
            get
            {
                return this.m_input;
            }
            private set
            {
                this.m_input = value;
            }
        }

        public FtpListItem LinkObject
        {
            get
            {
                return this.m_linkObject;
            }
            set
            {
                this.m_linkObject = value;
            }
        }

        public string LinkTarget
        {
            get
            {
                return this.m_linkTarget;
            }
            set
            {
                this.m_linkTarget = value;
            }
        }

        public DateTime Modified
        {
            get
            {
                return this.m_modified;
            }
            set
            {
                this.m_modified = value;
            }
        }

        public string Name
        {
            get
            {
                if ((this.m_name == null) && (this.m_path != null))
                {
                    return this.m_path.GetFtpFileName();
                }
                return this.m_name;
            }
            set
            {
                this.m_name = value;
            }
        }

        public FtpPermission OthersPermissions
        {
            get
            {
                return this.m_otherPermissions;
            }
            set
            {
                this.m_otherPermissions = value;
            }
        }

        public FtpPermission OwnerPermissions
        {
            get
            {
                return this.m_ownerPermissions;
            }
            set
            {
                this.m_ownerPermissions = value;
            }
        }

        private static Parser[] Parsers
        {
            get
            {
                lock (m_parserLock)
                {
                    if (m_parsers == null)
                    {
                        InitParsers();
                    }
                    return m_parsers.ToArray();
                }
            }
        }

        public long Size
        {
            get
            {
                return this.m_size;
            }
            set
            {
                this.m_size = value;
            }
        }

        public FtpSpecialPermissions SpecialPermissions
        {
            get
            {
                return this.m_specialPermissions;
            }
            set
            {
                this.m_specialPermissions = value;
            }
        }

        public FtpFileSystemObjectType Type
        {
            get
            {
                return this.m_type;
            }
            set
            {
                this.m_type = value;
            }
        }

        public delegate FtpListItem Parser(string line, FtpCapability capabilities);
    }
}

