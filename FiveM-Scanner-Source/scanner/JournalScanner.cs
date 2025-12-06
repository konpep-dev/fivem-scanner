using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace FiveMScanner
{
    public class JournalEntry
    {
        public string Location { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string Extension { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public DateTime Created { get; set; }
        public DateTime Modified { get; set; }
        public DateTime Accessed { get; set; }
        public string FullPath { get; set; } = string.Empty;
    }

    public class MFTEntry
    {
        public string FileName { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public DateTime Created { get; set; }
        public DateTime Modified { get; set; }
        public DateTime Accessed { get; set; }
        public string Attributes { get; set; } = string.Empty;
        public string FullPath { get; set; } = string.Empty;
    }

    public static class JournalScanner
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr FindFirstFile(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool FindNextFile(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindClose(IntPtr hFindFile);

        private const int INVALID_HANDLE_VALUE = -1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        public static List<JournalEntry> ScanJournal(int maxEntries = 500)
        {
            var journalEntries = new List<JournalEntry>();
            var username = Environment.UserName;

            var scanLocations = new Dictionary<string, string>
            {
                { $"C:\\Users\\{username}\\Downloads", "Downloads" },
                { $"C:\\Users\\{username}\\Desktop", "Desktop" },
                { "C:\\Windows\\Temp", "Windows Temp" },
                { "C:\\ProgramData", "ProgramData" }
            };

            foreach (var location in scanLocations)
            {
                if (journalEntries.Count >= maxEntries) break;
                if (!Directory.Exists(location.Key)) continue;

                try
                {
                    ScanDirectoryForJournal(location.Key, location.Value, journalEntries, maxEntries, 0);
                }
                catch
                {
                    // Skip access denied errors
                }
            }

            return journalEntries;
        }

        private static void ScanDirectoryForJournal(string dirPath, string label, List<JournalEntry> entries, int maxEntries, int depth)
        {
            if (depth > 3) return; // Limit recursion depth
            if (entries.Count >= maxEntries) return;

            try
            {
                var files = Directory.GetFiles(dirPath);
                foreach (var file in files)
                {
                    if (entries.Count >= maxEntries) break;

                    try
                    {
                        var fileInfo = new FileInfo(file);
                        var entry = new JournalEntry
                        {
                            Location = label,
                            FileName = fileInfo.Name,
                            Extension = fileInfo.Extension,
                            FileSize = fileInfo.Length,
                            Created = fileInfo.CreationTime,
                            Modified = fileInfo.LastWriteTime,
                            Accessed = fileInfo.LastAccessTime,
                            FullPath = file
                        };
                        entries.Add(entry);
                    }
                    catch
                    {
                        // Skip files we can't access
                    }
                }

                // Recurse into subdirectories
                var directories = Directory.GetDirectories(dirPath);
                foreach (var directory in directories)
                {
                    if (entries.Count >= maxEntries) break;

                    var dirName = Path.GetFileName(directory).ToLower();
                    // Skip system directories
                    if (dirName.Contains("system32") || dirName.Contains("winsxs")) continue;

                    ScanDirectoryForJournal(directory, label, entries, maxEntries, depth + 1);
                }
            }
            catch
            {
                // Skip access denied errors
            }
        }

        public static List<MFTEntry> ScanMFT(int maxEntries = 1000)
        {
            var mftEntries = new List<MFTEntry>();
            var username = Environment.UserName;

            var scanPaths = new List<string>
            {
                $"C:\\Users\\{username}\\Desktop",
                $"C:\\Users\\{username}\\Downloads",
                $"C:\\Users\\{username}\\Documents"
            };

            foreach (var basePath in scanPaths)
            {
                if (mftEntries.Count >= maxEntries) break;
                if (!Directory.Exists(basePath)) continue;

                try
                {
                    var files = Directory.GetFiles(basePath);
                    foreach (var file in files)
                    {
                        if (mftEntries.Count >= maxEntries) break;

                        try
                        {
                            var fileInfo = new FileInfo(file);
                            var attrs = new List<string>();

                            if ((fileInfo.Attributes & FileAttributes.Hidden) != 0) attrs.Add("Hidden");
                            if ((fileInfo.Attributes & FileAttributes.System) != 0) attrs.Add("System");
                            if ((fileInfo.Attributes & FileAttributes.ReadOnly) != 0) attrs.Add("ReadOnly");
                            if ((fileInfo.Attributes & FileAttributes.Archive) != 0) attrs.Add("Archive");

                            var entry = new MFTEntry
                            {
                                FileName = fileInfo.Name,
                                FileSize = fileInfo.Length,
                                Created = fileInfo.CreationTime,
                                Modified = fileInfo.LastWriteTime,
                                Accessed = fileInfo.LastAccessTime,
                                Attributes = attrs.Any() ? string.Join(" ", attrs) : "Normal",
                                FullPath = file
                            };
                            mftEntries.Add(entry);
                        }
                        catch
                        {
                            // Skip files we can't access
                        }
                    }
                }
                catch
                {
                    // Skip access denied errors
                }
            }

            return mftEntries;
        }
    }
}
