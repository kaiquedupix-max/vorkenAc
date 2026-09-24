using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Vorken.Agent;

internal static class UsnDeletionCollector
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;

    private const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;
    private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;

    private const uint USN_REASON_FILE_DELETE = 0x00000200;
    private const uint USN_REASON_RENAME_OLD_NAME = 0x00001000;

    public static List<DeletedUsnRecord> Collect()
    {
        var result = new List<DeletedUsnRecord>();

        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady ||
                    (drive.DriveType != DriveType.Fixed &&
                     drive.DriveType != DriveType.Removable) ||
                    !drive.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                result.AddRange(
                    CollectVolume(
                        drive.Name.TrimEnd('\\'),
                        drive.DriveType.ToString(),
                        maxRecords: 6000));
            }
            catch
            {
            }

            if (result.Count >= 10000)
                break;
        }

        return result
            .OrderByDescending(x => x.TimestampUtc)
            .GroupBy(
                x => $"{x.Volume}|{x.FileName}|{x.TimestampUtc:O}|{x.Reason}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(10000)
            .ToList();
    }

    private static List<DeletedUsnRecord> CollectVolume(
        string volume,
        string driveType,
        int maxRecords)
    {
        var result = new List<DeletedUsnRecord>();

        using SafeFileHandle handle = CreateFile(
            @"\\.\" + volume,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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

        // USN values advance with the journal stream. Reading only the tail
        // avoids walking years of changes while preserving recent deletions.
        long requestedWindow = 384L * 1024L * 1024L;
        long startUsn = Math.Max(
            journal.FirstUsn,
            journal.NextUsn - requestedWindow);

        var read = new READ_USN_JOURNAL_DATA_V0
        {
            StartUsn = startUsn,
            ReasonMask = USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME,
            ReturnOnlyOnClose = 0,
            Timeout = 0,
            BytesToWaitFor = 0,
            UsnJournalID = journal.UsnJournalID
        };

        byte[] buffer = new byte[1024 * 1024];
        DateTime cutoff = DateTime.UtcNow.AddDays(-120);

        for (int batch = 0; batch < 512 && result.Count < maxRecords; batch++)
        {
            if (!DeviceIoControlRead(
                    handle,
                    FSCTL_READ_USN_JOURNAL,
                    ref read,
                    Marshal.SizeOf<READ_USN_JOURNAL_DATA_V0>(),
                    buffer,
                    buffer.Length,
                    out int bytesReturned,
                    IntPtr.Zero))
            {
                break;
            }

            if (bytesReturned <= sizeof(long))
                break;

            long nextUsn = BitConverter.ToInt64(buffer, 0);
            int offset = sizeof(long);

            while (offset + 8 <= bytesReturned &&
                   result.Count < maxRecords)
            {
                uint recordLength = BitConverter.ToUInt32(buffer, offset);
                if (recordLength < 60 ||
                    offset + recordLength > bytesReturned)
                {
                    break;
                }

                ushort majorVersion = BitConverter.ToUInt16(buffer, offset + 4);

                if (majorVersion == 2)
                {
                    ParseV2(
                        buffer,
                        offset,
                        recordLength,
                        volume,
                        driveType,
                        cutoff,
                        result);
                }

                offset += checked((int)recordLength);
            }

            if (nextUsn <= read.StartUsn ||
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
        string driveType,
        DateTime cutoff,
        List<DeletedUsnRecord> target)
    {
        try
        {
            ulong fileReference = BitConverter.ToUInt64(buffer, offset + 8);
            ulong parentReference = BitConverter.ToUInt64(buffer, offset + 16);
            long usn = BitConverter.ToInt64(buffer, offset + 24);
            long fileTime = BitConverter.ToInt64(buffer, offset + 32);
            uint reason = BitConverter.ToUInt32(buffer, offset + 40);
            ushort nameLength = BitConverter.ToUInt16(buffer, offset + 56);
            ushort nameOffset = BitConverter.ToUInt16(buffer, offset + 58);

            bool deleted = (reason & USN_REASON_FILE_DELETE) != 0;
            bool renamed = (reason & USN_REASON_RENAME_OLD_NAME) != 0;

            if (!deleted && !renamed)
                return;

            if (nameLength == 0 ||
                nameOffset + nameLength > recordLength)
            {
                return;
            }

            string name = System.Text.Encoding.Unicode.GetString(
                buffer,
                offset + nameOffset,
                nameLength);

            if (string.IsNullOrWhiteSpace(name))
                return;

            DateTime timestamp;
            try
            {
                timestamp = DateTime.FromFileTimeUtc(fileTime);
            }
            catch
            {
                return;
            }

            if (timestamp < cutoff ||
                timestamp > DateTime.UtcNow.AddDays(2))
            {
                return;
            }

            string extension = Path.GetExtension(name).ToLowerInvariant();

            bool riskyExtension = extension is
                ".exe" or ".com" or ".scr" or ".dll" or ".sys" or
                ".msi" or ".bat" or ".cmd" or
                ".zip" or ".rar" or ".7z";

            if (!riskyExtension)
                return;

            target.Add(new DeletedUsnRecord
            {
                Volume = volume,
                DriveType = driveType,
                FileName = name,
                Extension = extension,
                TimestampUtc = timestamp,
                Reason = deleted ? "FILE_DELETE" : "RENAME_OLD_NAME",
                Usn = usn,
                FileReferenceNumber = fileReference,
                ParentFileReferenceNumber = parentReference,
                RandomLikeName = LooksRandomExecutableName(name),
                DeceptiveDoubleExtension = IsDoubleExtension(name)
            });
        }
        catch
        {
        }
    }

    private static bool IsDoubleExtension(string value) =>
        Regex.IsMatch(
            Path.GetFileName(value),
            @"\.(zip|rar|7z|pdf|jpg|jpeg|png|gif|txt|doc|docx|xls|xlsx|ppt|pptx)\.exe$",
            RegexOptions.IgnoreCase);

    private static bool LooksRandomExecutableName(string value)
    {
        if (!Path.GetExtension(value)
                .Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string stem = Path.GetFileNameWithoutExtension(value);

        if (
            IsGenericInstallerStem(stem) ||
            HasReadableExecutableToken(stem))
        {
            return false;
        }

        stem = Regex.Replace(
            stem,
            @"\.(zip|rar|7z|pdf|jpg|jpeg|png|txt)$",
            "",
            RegexOptions.IgnoreCase);

        if (stem.Length < 4 || stem.Length > 28 ||
            !stem.All(char.IsLetterOrDigit))
        {
            return false;
        }

        int letters = stem.Count(char.IsLetter);
        int digits = stem.Count(char.IsDigit);
        int vowels = stem.Count(ch => "aeiouAEIOU".Contains(ch));
        int distinct = stem.ToUpperInvariant().Distinct().Count();

        bool allUpperOrDigits = stem.All(ch =>
            char.IsDigit(ch) || char.IsUpper(ch));

        double vowelRatio = letters > 0
            ? (double)vowels / letters
            : 0;

        if (stem.Length <= 5)
        {
            return
                allUpperOrDigits &&
                distinct >= Math.Max(4, stem.Length - 1) &&
                (digits >= 1 || vowels == 0) &&
                vowelRatio <= 0.25;
        }

        if (
            allUpperOrDigits &&
            distinct >= Math.Min(6, stem.Length - 1) &&
            (
                digits >= 1
                    ? vowelRatio <= 0.35
                    : vowelRatio <= 0.12
            ))
        {
            return true;
        }

        if (
            stem.Length >= 8 &&
            stem.Length <= 18 &&
            digits == 0 &&
            letters == stem.Length &&
            distinct >= 7 &&
            vowelRatio <= 0.22)
        {
            return true;
        }

        int transitions = 0;
        for (int i = 1; i < stem.Length; i++)
        {
            bool previousDigit = char.IsDigit(stem[i - 1]);
            bool currentDigit = char.IsDigit(stem[i]);

            if (previousDigit != currentDigit)
                transitions++;
        }

        bool trailingDigitsOnly =
            Regex.IsMatch(
                stem,
                @"^[A-Za-z]+[0-9]{1,4}$");

        if (
            trailingDigitsOnly &&
            letters >= 5 &&
            vowelRatio >= 0.16)
        {
            return false;
        }

        return
            stem.Length >= 10 &&
            letters >= 6 &&
            digits >= 2 &&
            distinct >= 8 &&
            (
                transitions >= 3 ||
                vowelRatio <= 0.12
            );
    }

    private static bool IsGenericInstallerStem(string value)
    {
        string stem = (value ?? "").Trim().ToLowerInvariant();

        return stem is
            "installer" or
            "install" or
            "setup" or
            "setup64" or
            "setup32" or
            "updater" or
            "update" or
            "uninstall" or
            "uninstaller" or
            "bootstrapper" or
            "launcherinstaller";
    }

    private static bool HasReadableExecutableToken(string value)
    {
        string stem = (value ?? "")
            .ToLowerInvariant()
            .Replace("_", "")
            .Replace("-", "")
            .Replace(".", "");

        string[] tokens =
        {
            "installer", "install", "setup", "updater", "update",
            "uninstall", "bootstrapper", "launcher", "browser",
            "microsoft", "windows", "store", "opera", "avast",
            "crystal", "disk", "info", "control", "driver", "client",
            "helper", "service", "runtime", "manager", "discord",
            "chrome", "edge", "steam", "spotify", "firefox",
            "nvidia", "amd", "intel"
        };

        return tokens.Any(token =>
            token.Length >= 4 &&
            stem.Contains(token, StringComparison.OrdinalIgnoreCase));
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

internal sealed class DeletedUsnRecord
{
    public string Volume { get; set; } = "";
    public string DriveType { get; set; } = "";
    public string FileName { get; set; } = "";
    public string Extension { get; set; } = "";
    public DateTime TimestampUtc { get; set; }
    public string Reason { get; set; } = "";
    public long Usn { get; set; }
    public ulong FileReferenceNumber { get; set; }
    public ulong ParentFileReferenceNumber { get; set; }
    public bool RandomLikeName { get; set; }
    public bool DeceptiveDoubleExtension { get; set; }
}
