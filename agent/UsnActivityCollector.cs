using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Vorken.Agent;

internal static class UsnActivityCollector
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_READ_ATTRIBUTES = 0x00000080;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    private const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;
    private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;

    private const uint USN_REASON_DATA_OVERWRITE = 0x00000001;
    private const uint USN_REASON_DATA_EXTEND = 0x00000002;
    private const uint USN_REASON_DATA_TRUNCATION = 0x00000004;
    private const uint USN_REASON_FILE_CREATE = 0x00000100;
    private const uint USN_REASON_FILE_DELETE = 0x00000200;
    private const uint USN_REASON_RENAME_OLD_NAME = 0x00001000;
    private const uint USN_REASON_RENAME_NEW_NAME = 0x00002000;
    private const uint USN_REASON_CLOSE = 0x80000000;

    private const ulong MftIndexMask = 0x0000FFFFFFFFFFFFUL;

    private static readonly HashSet<string> InterestingExtensions =
        new(
            new[]
            {
                ".exe", ".com", ".scr", ".dll", ".sys", ".msi",
                ".bat", ".cmd", ".ps1", ".zip", ".rar", ".7z",
                ".pf", ".evtx", ".db", ".dat", ".hve", ".lnk"
            },
            StringComparer.OrdinalIgnoreCase);

    public static List<UsnActivityRecord> Collect()
    {
        var result = new List<UsnActivityRecord>();

        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady ||
                    (drive.DriveType != DriveType.Fixed &&
                     drive.DriveType != DriveType.Removable) ||
                    !drive.DriveFormat.Equals(
                        "NTFS",
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string volume =
                    drive.Name.TrimEnd('\\');

                ulong? prefetchIndex = null;

                string windows =
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.Windows);

                if (
                    !string.IsNullOrWhiteSpace(windows) &&
                    windows.StartsWith(
                        volume,
                        StringComparison.OrdinalIgnoreCase))
                {
                    prefetchIndex =
                        GetFileIndex(
                            Path.Combine(
                                windows,
                                "Prefetch"));
                }

                result.AddRange(
                    CollectVolume(
                        volume,
                        prefetchIndex,
                        12000));
            }
            catch
            {
            }

            if (result.Count >= 18000)
                break;
        }

        return result
            .OrderByDescending(x => x.TimestampUtc)
            .GroupBy(
                x =>
                    $"{x.Volume}|{x.FileName}|{x.TimestampUtc:O}|{x.ReasonMask}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(18000)
            .ToList();
    }

    private static List<UsnActivityRecord> CollectVolume(
        string volume,
        ulong? prefetchIndex,
        int maxRecords)
    {
        var result = new List<UsnActivityRecord>();

        using SafeFileHandle handle =
            CreateFile(
                @"\\.\" + volume,
                GENERIC_READ,
                FILE_SHARE_READ |
                FILE_SHARE_WRITE |
                FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

        if (handle.IsInvalid)
            return result;

        if (!DeviceIoControlQuery(
                handle,
                FSCTL_QUERY_USN_JOURNAL,
                IntPtr.Zero,
                0,
                out USN_JOURNAL_DATA_V0 journal,
                Marshal.SizeOf<USN_JOURNAL_DATA_V0>(),
                out _,
                IntPtr.Zero))
        {
            return result;
        }

        long requestedWindow =
            512L * 1024L * 1024L;

        long startUsn =
            Math.Max(
                journal.FirstUsn,
                journal.NextUsn - requestedWindow);

        uint reasonMask =
            USN_REASON_DATA_OVERWRITE |
            USN_REASON_DATA_EXTEND |
            USN_REASON_DATA_TRUNCATION |
            USN_REASON_FILE_CREATE |
            USN_REASON_FILE_DELETE |
            USN_REASON_RENAME_OLD_NAME |
            USN_REASON_RENAME_NEW_NAME |
            USN_REASON_CLOSE;

        var read =
            new READ_USN_JOURNAL_DATA_V0
            {
                StartUsn = startUsn,
                ReasonMask = reasonMask,
                ReturnOnlyOnClose = 0,
                Timeout = 0,
                BytesToWaitFor = 0,
                UsnJournalID =
                    journal.UsnJournalID
            };

        byte[] buffer =
            new byte[1024 * 1024];

        DateTime cutoff =
            DateTime.UtcNow.AddDays(-45);

        for (
            int batch = 0;
            batch < 800 &&
            result.Count < maxRecords;
            batch++)
        {
            if (!DeviceIoControlRead(
                    handle,
                    FSCTL_READ_USN_JOURNAL,
                    ref read,
                    Marshal.SizeOf<
                        READ_USN_JOURNAL_DATA_V0>(),
                    buffer,
                    buffer.Length,
                    out int bytesReturned,
                    IntPtr.Zero))
            {
                break;
            }

            if (bytesReturned <= sizeof(long))
                break;

            long nextUsn =
                BitConverter.ToInt64(
                    buffer,
                    0);

            int offset =
                sizeof(long);

            while (
                offset + 8 <= bytesReturned &&
                result.Count < maxRecords)
            {
                uint recordLength =
                    BitConverter.ToUInt32(
                        buffer,
                        offset);

                if (
                    recordLength < 60 ||
                    offset + recordLength >
                    bytesReturned)
                {
                    break;
                }

                ushort majorVersion =
                    BitConverter.ToUInt16(
                        buffer,
                        offset + 4);

                if (majorVersion == 2)
                {
                    ParseV2(
                        buffer,
                        offset,
                        recordLength,
                        volume,
                        prefetchIndex,
                        cutoff,
                        result);
                }

                offset +=
                    checked((int)recordLength);
            }

            if (
                nextUsn <= read.StartUsn ||
                nextUsn >= journal.NextUsn)
            {
                break;
            }

            read.StartUsn = nextUsn;
        }

        return result;
    }

    private static void ParseV2(
        byte[] buffer,
        int offset,
        uint recordLength,
        string volume,
        ulong? prefetchIndex,
        DateTime cutoff,
        List<UsnActivityRecord> target)
    {
        try
        {
            ulong fileReference =
                BitConverter.ToUInt64(
                    buffer,
                    offset + 8);

            ulong parentReference =
                BitConverter.ToUInt64(
                    buffer,
                    offset + 16);

            long usn =
                BitConverter.ToInt64(
                    buffer,
                    offset + 24);

            long fileTime =
                BitConverter.ToInt64(
                    buffer,
                    offset + 32);

            uint reason =
                BitConverter.ToUInt32(
                    buffer,
                    offset + 40);

            ushort nameLength =
                BitConverter.ToUInt16(
                    buffer,
                    offset + 56);

            ushort nameOffset =
                BitConverter.ToUInt16(
                    buffer,
                    offset + 58);

            if (
                nameLength == 0 ||
                nameOffset + nameLength >
                recordLength)
            {
                return;
            }

            string name =
                System.Text.Encoding.Unicode.GetString(
                    buffer,
                    offset + nameOffset,
                    nameLength);

            if (string.IsNullOrWhiteSpace(name))
                return;

            DateTime timestamp;

            try
            {
                timestamp =
                    DateTime.FromFileTimeUtc(
                        fileTime);
            }
            catch
            {
                return;
            }

            if (
                timestamp < cutoff ||
                timestamp >
                    DateTime.UtcNow.AddDays(2))
            {
                return;
            }

            string extension =
                Path.GetExtension(name)
                    .ToLowerInvariant();

            bool interesting =
                InterestingExtensions.Contains(
                    extension);

            bool browserDatabase =
                name.Equals(
                    "History",
                    StringComparison.OrdinalIgnoreCase) ||
                name.Equals(
                    "places.sqlite",
                    StringComparison.OrdinalIgnoreCase) ||
                name.Equals(
                    "Cookies",
                    StringComparison.OrdinalIgnoreCase);

            bool windowsForensicArtifact =
                extension is
                    ".pf" or
                    ".evtx" or
                    ".hve" ||
                name.Equals(
                    "SRUDB.dat",
                    StringComparison.OrdinalIgnoreCase) ||
                name.Contains(
                    "ActivitiesCache",
                    StringComparison.OrdinalIgnoreCase);

            if (
                !interesting &&
                !browserDatabase &&
                !windowsForensicArtifact)
            {
                return;
            }

            ulong parentIndex =
                parentReference &
                MftIndexMask;

            bool underPrefetch =
                prefetchIndex.HasValue &&
                parentIndex ==
                    prefetchIndex.Value;

            target.Add(
                new UsnActivityRecord
                {
                    Volume = volume,
                    FileName = name,
                    Extension = extension,
                    TimestampUtc = timestamp,
                    Usn = usn,
                    FileReferenceNumber =
                        fileReference,
                    ParentFileReferenceNumber =
                        parentReference,
                    ReasonMask = reason,
                    Reasons =
                        DescribeReasons(reason),
                    Deleted =
                        (reason &
                         USN_REASON_FILE_DELETE) != 0,
                    Created =
                        (reason &
                         USN_REASON_FILE_CREATE) != 0,
                    Renamed =
                        (reason &
                         (
                            USN_REASON_RENAME_OLD_NAME |
                            USN_REASON_RENAME_NEW_NAME
                         )) != 0,
                    Modified =
                        (reason &
                         (
                            USN_REASON_DATA_OVERWRITE |
                            USN_REASON_DATA_EXTEND |
                            USN_REASON_DATA_TRUNCATION
                         )) != 0,
                    UnderPrefetchDirectory =
                        underPrefetch,
                    BrowserDatabase =
                        browserDatabase,
                    WindowsForensicArtifact =
                        windowsForensicArtifact
                });
        }
        catch
        {
        }
    }

    private static List<string> DescribeReasons(
        uint reason)
    {
        var result = new List<string>();

        void Add(
            uint mask,
            string label)
        {
            if ((reason & mask) != 0)
                result.Add(label);
        }

        Add(
            USN_REASON_DATA_OVERWRITE,
            "DATA_OVERWRITE");

        Add(
            USN_REASON_DATA_EXTEND,
            "DATA_EXTEND");

        Add(
            USN_REASON_DATA_TRUNCATION,
            "DATA_TRUNCATION");

        Add(
            USN_REASON_FILE_CREATE,
            "FILE_CREATE");

        Add(
            USN_REASON_FILE_DELETE,
            "FILE_DELETE");

        Add(
            USN_REASON_RENAME_OLD_NAME,
            "RENAME_OLD_NAME");

        Add(
            USN_REASON_RENAME_NEW_NAME,
            "RENAME_NEW_NAME");

        Add(
            USN_REASON_CLOSE,
            "CLOSE");

        return result;
    }

    private static ulong? GetFileIndex(
        string path)
    {
        if (!Directory.Exists(path))
            return null;

        using SafeFileHandle handle =
            CreateFile(
                path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ |
                FILE_SHARE_WRITE |
                FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);

        if (handle.IsInvalid)
            return null;

        if (!GetFileInformationByHandle(
                handle,
                out BY_HANDLE_FILE_INFORMATION info))
        {
            return null;
        }

        ulong fileIndex =
            ((ulong)info.FileIndexHigh << 32) |
            info.FileIndexLow;

        return fileIndex & MftIndexMask;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct USN_JOURNAL_DATA_V0
    {
        public ulong UsnJournalID;
        public long FirstUsn;
        public long NextUsn;
        public long LowestValidUsn;
        public long MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct READ_USN_JOURNAL_DATA_V0
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalID;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out BY_HANDLE_FILE_INFORMATION lpFileInformation);

    [DllImport(
        "kernel32.dll",
        SetLastError = true,
        EntryPoint = "DeviceIoControl")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControlQuery(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        int nInBufferSize,
        out USN_JOURNAL_DATA_V0 lpOutBuffer,
        int nOutBufferSize,
        out int lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport(
        "kernel32.dll",
        SetLastError = true,
        EntryPoint = "DeviceIoControl")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControlRead(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        ref READ_USN_JOURNAL_DATA_V0 lpInBuffer,
        int nInBufferSize,
        [Out] byte[] lpOutBuffer,
        int nOutBufferSize,
        out int lpBytesReturned,
        IntPtr lpOverlapped);
}

internal sealed class UsnActivityRecord
{
    public string Volume { get; set; } = "";
    public string FileName { get; set; } = "";
    public string Extension { get; set; } = "";
    public DateTime TimestampUtc { get; set; }
    public long Usn { get; set; }
    public ulong FileReferenceNumber { get; set; }
    public ulong ParentFileReferenceNumber { get; set; }
    public uint ReasonMask { get; set; }
    public List<string> Reasons { get; set; } = new();
    public bool Deleted { get; set; }
    public bool Created { get; set; }
    public bool Renamed { get; set; }
    public bool Modified { get; set; }
    public bool UnderPrefetchDirectory { get; set; }
    public bool BrowserDatabase { get; set; }
    public bool WindowsForensicArtifact { get; set; }
}
