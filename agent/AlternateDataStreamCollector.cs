using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Vorken.Agent;

internal static class AlternateDataStreamCollector
{
    private const int FindStreamInfoStandard = 0;

    public static List<AlternateDataStreamRecord> Collect(
        List<FileRecord> files)
    {
        var result = new List<AlternateDataStreamRecord>();

        foreach (FileRecord file in files)
        {
            if (result.Count >= 2500)
                break;

            if (string.IsNullOrWhiteSpace(file.Path) ||
                !File.Exists(file.Path))
            {
                continue;
            }

            try
            {
                CollectFile(file.Path, result);
            }
            catch
            {
            }
        }

        return result
            .GroupBy(
                x => $"{x.Path}|{x.StreamName}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(2500)
            .ToList();
    }

    private static void CollectFile(
        string path,
        List<AlternateDataStreamRecord> result)
    {
        WIN32_FIND_STREAM_DATA data;

        using SafeFindHandle handle = FindFirstStreamW(
            path,
            FindStreamInfoStandard,
            out data,
            0);

        if (handle.IsInvalid)
            return;

        while (true)
        {
            string stream = data.cStreamName ?? "";

            if (!IsDefaultStream(stream) &&
                !IsZoneIdentifier(stream))
            {
                string cleanName =
                    stream.Trim(':')
                        .Replace(":$DATA", "",
                            StringComparison.OrdinalIgnoreCase);

                bool executableLike =
                    Regex.IsMatch(
                        cleanName,
                        @"\.(exe|dll|sys|com|scr|bat|cmd|ps1|msi)$",
                        RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(
                        stream,
                        @"\.(exe|dll|sys|com|scr|bat|cmd|ps1|msi):\$DATA$",
                        RegexOptions.IgnoreCase);

                bool suspiciousName =
                    executableLike ||
                    cleanName.Contains(
                        "loader",
                        StringComparison.OrdinalIgnoreCase) ||
                    cleanName.Contains(
                        "inject",
                        StringComparison.OrdinalIgnoreCase) ||
                    cleanName.Contains(
                        "cheat",
                        StringComparison.OrdinalIgnoreCase) ||
                    cleanName.Contains(
                        "script",
                        StringComparison.OrdinalIgnoreCase);

                result.Add(new AlternateDataStreamRecord
                {
                    Path = path,
                    StreamName = stream,
                    StreamSize = data.StreamSize,
                    ExecutableLike = executableLike,
                    Suspicious = suspiciousName
                });
            }

            if (!FindNextStreamW(
                    handle,
                    out data))
            {
                break;
            }
        }
    }

    private static bool IsDefaultStream(string value) =>
        value.Equals(
            "::$DATA",
            StringComparison.OrdinalIgnoreCase);

    private static bool IsZoneIdentifier(string value) =>
        value.Contains(
            "Zone.Identifier",
            StringComparison.OrdinalIgnoreCase);

    [StructLayout(
        LayoutKind.Sequential,
        CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;

        [MarshalAs(
            UnmanagedType.ByValTStr,
            SizeConst = 296)]
        public string cStreamName;
    }

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFindHandle FindFirstStreamW(
        string lpFileName,
        int infoLevel,
        out WIN32_FIND_STREAM_DATA lpFindStreamData,
        int dwFlags);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextStreamW(
        SafeFindHandle hFindStream,
        out WIN32_FIND_STREAM_DATA lpFindStreamData);

    private sealed class SafeFindHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeFindHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle() =>
            FindClose(handle);

        [DllImport(
            "kernel32.dll",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindClose(
            IntPtr hFindFile);
    }
}

internal sealed class AlternateDataStreamRecord
{
    public string Path { get; set; } = "";
    public string StreamName { get; set; } = "";
    public long StreamSize { get; set; }
    public bool ExecutableLike { get; set; }
    public bool Suspicious { get; set; }
}
