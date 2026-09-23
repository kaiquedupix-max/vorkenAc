using System.Runtime.InteropServices;
using System.Text;

namespace Vorken.Agent;

internal static class PrefetchExecutionCollector
{
    public static List<PrefetchExecutionRecord> Collect()
    {
        string directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Prefetch");

        var result = new List<PrefetchExecutionRecord>();
        if (!Directory.Exists(directory)) return result;

        var deviceMap = GetDosDeviceMap();
        string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        string? systemDevice = QueryDevice(systemDrive);
        string? systemVolumeGuid = QueryVolumeGuid(systemDrive);
        var systemAliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(systemDevice))
            systemAliases.Add(NormalizeDevice(systemDevice));

        if (!string.IsNullOrWhiteSpace(systemVolumeGuid))
            systemAliases.Add(NormalizeDevice(systemVolumeGuid));

        foreach (string file in Directory
                     .EnumerateFiles(directory, "*.pf", SearchOption.TopDirectoryOnly)
                     .OrderByDescending(x => SafeLastWriteUtc(x))
                     .Take(1500))
        {
            try
            {
                using var stream = new FileStream(
                    file,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);

                var pf = global::Prefetch.PrefetchFile.Open(stream, file);
                string executableName = pf.Header.ExecutableFilename ?? "";

                string? nativeExecutablePath = pf.Filenames
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .FirstOrDefault(x =>
                        x.EndsWith("\\" + executableName, StringComparison.OrdinalIgnoreCase) ||
                        x.Equals(executableName, StringComparison.OrdinalIgnoreCase));

                string? resolvedPath = ResolveNativePath(nativeExecutablePath, deviceMap);
                bool? executablePresent = null;

                if (!string.IsNullOrWhiteSpace(resolvedPath))
                {
                    try { executablePresent = File.Exists(resolvedPath); }
                    catch { executablePresent = null; }
                }

                DateTime? lastRunUtc = pf.LastRunTimes
                    .OrderByDescending(x => x.UtcDateTime)
                    .Select(x => (DateTime?)x.UtcDateTime)
                    .FirstOrDefault();

                var volumes = pf.VolumeInformation
                    .Select(v =>
                    {
                        string deviceName = v.DeviceName ?? "";
                        string serialNumber = v.SerialNumber ?? "";
                        string normalized = NormalizeDevice(deviceName);

                        deviceMap.TryGetValue(normalized, out var mapped);

                        if (mapped is null &&
                            !string.IsNullOrWhiteSpace(serialNumber))
                        {
                            deviceMap.TryGetValue(
                                "SERIAL:" + NormalizeSerial(serialNumber),
                                out mapped);
                        }

                        return new PrefetchVolumeRecord
                        {
                            DeviceName = deviceName,
                            SerialNumber = serialNumber,
                            CreationTimeUtc = v.CreationTime.UtcDateTime,
                            CurrentDriveLetter = mapped?.DriveLetter,
                            CurrentDriveType = mapped?.DriveType,
                            CurrentlyMounted = mapped is not null
                        };
                    })
                    .ToList();

                PrefetchVolumeRecord? executableVolume = null;

                if (!string.IsNullOrWhiteSpace(nativeExecutablePath))
                {
                    executableVolume = volumes
                        .OrderByDescending(v => v.DeviceName.Length)
                        .FirstOrDefault(v =>
                            nativeExecutablePath.StartsWith(
                                v.DeviceName,
                                StringComparison.OrdinalIgnoreCase));
                }

                bool volumeNotMounted =
                    executableVolume is not null &&
                    !executableVolume.CurrentlyMounted;

                bool currentRemovable =
                    executableVolume?.CurrentDriveType?.Equals(
                        DriveType.Removable.ToString(),
                        StringComparison.OrdinalIgnoreCase) == true;

                bool nativeLooksLikeWindowsSystemPath =
                    LooksLikeWindowsSystemPath(nativeExecutablePath, resolvedPath);

                bool nonSystemVolume =
                    executableVolume is not null &&
                    (
                        string.IsNullOrWhiteSpace(executableVolume.CurrentDriveLetter)
                            ? !systemAliases.Contains(NormalizeDevice(executableVolume.DeviceName))
                            : !executableVolume.CurrentDriveLetter.Equals(
                                systemDrive.TrimEnd('\\'),
                                StringComparison.OrdinalIgnoreCase)
                    );

                bool likelyDetachedOrRemovable =
                    !nativeLooksLikeWindowsSystemPath &&
                    (
                        currentRemovable ||
                        (volumeNotMounted && nonSystemVolume)
                    );

                result.Add(new PrefetchExecutionRecord
                {
                    ExecutableName = executableName,
                    PrefetchFile = Path.GetFileName(file),
                    PrefetchHash = pf.Header.Hash ?? "",
                    Version = pf.Header.Version.ToString(),
                    RunCount = pf.RunCount,
                    LastRunTimesUtc = pf.LastRunTimes
                        .OrderByDescending(x => x.UtcDateTime)
                        .Take(8)
                        .Select(x => x.UtcDateTime)
                        .ToList(),
                    LastRunUtc = lastRunUtc,
                    NativeExecutablePath = nativeExecutablePath,
                    ResolvedExecutablePath = resolvedPath,
                    ExecutablePresent = executablePresent,
                    VolumeNotMounted = volumeNotMounted,
                    CurrentRemovable = currentRemovable,
                    NonSystemVolume = nonSystemVolume,
                    LikelyDetachedOrRemovable = likelyDetachedOrRemovable,
                    Volumes = volumes
                });
            }
            catch
            {
            }
        }

        return result
            .OrderByDescending(x => x.LastRunUtc ?? DateTime.MinValue)
            .Take(1200)
            .ToList();
    }

    private static Dictionary<string, DosDeviceRecord> GetDosDeviceMap()
    {
        var result = new Dictionary<string, DosDeviceRecord>(StringComparer.OrdinalIgnoreCase);

        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            string driveLetter = drive.Name.TrimEnd('\\');
            string? device = QueryDevice(driveLetter);
            if (string.IsNullOrWhiteSpace(device)) continue;

            var record = new DosDeviceRecord
            {
                DriveLetter = driveLetter,
                DevicePath = device,
                VolumeGuidPath = QueryVolumeGuid(driveLetter) ?? "",
                VolumeSerialNumber = QueryVolumeSerial(driveLetter) ?? "",
                DriveType = drive.DriveType.ToString()
            };

            result[NormalizeDevice(device)] = record;

            if (!string.IsNullOrWhiteSpace(record.VolumeGuidPath))
                result[NormalizeDevice(record.VolumeGuidPath)] = record;

            if (!string.IsNullOrWhiteSpace(record.VolumeSerialNumber))
                result["SERIAL:" + NormalizeSerial(record.VolumeSerialNumber)] = record;
        }

        return result;
    }

    private static string? ResolveNativePath(
        string? nativePath,
        Dictionary<string, DosDeviceRecord> deviceMap)
    {
        if (string.IsNullOrWhiteSpace(nativePath)) return null;

        string normalizedNative = NormalizeDevice(nativePath);

        foreach (var pair in deviceMap
                     .OrderByDescending(x => x.Key.Length))
        {
            if (!normalizedNative.StartsWith(
                    pair.Key,
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string suffix = normalizedNative[pair.Key.Length..]
                .TrimStart('\\');

            return pair.Value.DriveLetter + "\\" + suffix;
        }

        return null;
    }

    private static string? QueryDevice(string driveLetter)
    {
        try
        {
            var buffer = new StringBuilder(1024);
            uint result = QueryDosDevice(
                driveLetter.TrimEnd('\\'),
                buffer,
                buffer.Capacity);

            return result == 0 ? null : buffer.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static string? QueryVolumeGuid(string driveLetter)
    {
        try
        {
            string mountPoint = driveLetter.TrimEnd('\\') + "\\";
            var buffer = new StringBuilder(1024);

            return GetVolumeNameForVolumeMountPoint(
                mountPoint,
                buffer,
                buffer.Capacity)
                ? buffer.ToString()
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? QueryVolumeSerial(string driveLetter)
    {
        try
        {
            string root = driveLetter.TrimEnd('\\') + "\\";
            var volumeName = new StringBuilder(261);
            var fileSystemName = new StringBuilder(261);

            if (!GetVolumeInformation(
                    root,
                    volumeName,
                    volumeName.Capacity,
                    out uint serial,
                    out _,
                    out _,
                    fileSystemName,
                    fileSystemName.Capacity))
            {
                return null;
            }

            return serial.ToString("X8");
        }
        catch
        {
            return null;
        }
    }

    private static string NormalizeSerial(string? value) =>
        new string((value ?? "")
            .Where(char.IsLetterOrDigit)
            .ToArray())
            .ToUpperInvariant();

    private static bool LooksLikeWindowsSystemPath(
        string? nativePath,
        string? resolvedPath)
    {
        string windows = Environment.GetFolderPath(
            Environment.SpecialFolder.Windows);

        if (!string.IsNullOrWhiteSpace(resolvedPath) &&
            !string.IsNullOrWhiteSpace(windows))
        {
            try
            {
                string fullResolved = Path.GetFullPath(resolvedPath);
                string fullWindows = Path.GetFullPath(windows)
                    .TrimEnd(Path.DirectorySeparatorChar) +
                    Path.DirectorySeparatorChar;

                if (fullResolved.StartsWith(
                    fullWindows,
                    StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            catch
            {
            }
        }

        string normalizedNative = NormalizeDevice(nativePath);

        return normalizedNative.Contains(
                   @"\WINDOWS\",
                   StringComparison.OrdinalIgnoreCase) ||
               normalizedNative.EndsWith(
                   @"\WINDOWS",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeDevice(string? value)
    {
        string normalized = (value ?? "")
            .Trim()
            .TrimEnd('\\')
            .ToUpperInvariant();

        if (normalized.StartsWith(@"\\?\VOLUME{", StringComparison.OrdinalIgnoreCase))
            normalized = "\\" + normalized[4..];

        return normalized;
    }

    private static DateTime SafeLastWriteUtc(string path)
    {
        try { return File.GetLastWriteTimeUtc(path); }
        catch { return DateTime.MinValue; }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(
        string? lpDeviceName,
        StringBuilder lpTargetPath,
        int ucchMax);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPoint(
        string lpszVolumeMountPoint,
        StringBuilder lpszVolumeName,
        int cchBufferLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformation(
        string lpRootPathName,
        StringBuilder lpVolumeNameBuffer,
        int nVolumeNameSize,
        out uint lpVolumeSerialNumber,
        out uint lpMaximumComponentLength,
        out uint lpFileSystemFlags,
        StringBuilder lpFileSystemNameBuffer,
        int nFileSystemNameSize);
}

internal sealed class DosDeviceRecord
{
    public string DriveLetter { get; set; } = "";
    public string DevicePath { get; set; } = "";
    public string VolumeGuidPath { get; set; } = "";
    public string VolumeSerialNumber { get; set; } = "";
    public string DriveType { get; set; } = "";
}

internal sealed class PrefetchExecutionRecord
{
    public string ExecutableName { get; set; } = "";
    public string PrefetchFile { get; set; } = "";
    public string PrefetchHash { get; set; } = "";
    public string Version { get; set; } = "";
    public int RunCount { get; set; }
    public List<DateTime> LastRunTimesUtc { get; set; } = new();
    public DateTime? LastRunUtc { get; set; }
    public string? NativeExecutablePath { get; set; }
    public string? ResolvedExecutablePath { get; set; }
    public bool? ExecutablePresent { get; set; }
    public bool VolumeNotMounted { get; set; }
    public bool CurrentRemovable { get; set; }
    public bool NonSystemVolume { get; set; }
    public bool LikelyDetachedOrRemovable { get; set; }
    public List<PrefetchVolumeRecord> Volumes { get; set; } = new();
}

internal sealed class PrefetchVolumeRecord
{
    public string DeviceName { get; set; } = "";
    public string SerialNumber { get; set; } = "";
    public DateTime CreationTimeUtc { get; set; }
    public string? CurrentDriveLetter { get; set; }
    public string? CurrentDriveType { get; set; }
    public bool CurrentlyMounted { get; set; }
}
