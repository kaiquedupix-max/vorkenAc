using Microsoft.Win32;
using System.Diagnostics;
using System.Management;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Vorken.Agent;

internal static class DeepForensicCollector
{
    public static List<ProcessCreationRecord> CollectProcessCreationEvents()
    {
        var result = new List<ProcessCreationRecord>();

        foreach (string xml in QueryEvents(
                     "Security",
                     "*[System[(EventID=4688)]]",
                     700,
                     15000))
        {
            try
            {
                XDocument doc = XDocument.Parse(xml);
                XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
                DateTime timeUtc = EventTime(doc, ns);

                var data = EventData(doc, ns);

                string processPath = GetData(data, "NewProcessName");
                string parentPath = GetData(data, "ParentProcessName");

                if (string.IsNullOrWhiteSpace(processPath))
                    continue;

                result.Add(new ProcessCreationRecord
                {
                    TimeCreatedUtc = timeUtc,
                    ProcessPath = processPath,
                    ProcessName = Path.GetFileName(processPath),
                    ParentProcessPath = parentPath,
                    ParentProcessName = Path.GetFileName(parentPath)
                });
            }
            catch
            {
            }
        }

        return result
            .OrderByDescending(x => x.TimeCreatedUtc)
            .Take(700)
            .ToList();
    }

    public static List<DefenderDetectionRecord> CollectDefenderDetections()
    {
        var result = new List<DefenderDetectionRecord>();

        foreach (string xml in QueryEvents(
                     "Microsoft-Windows-Windows Defender/Operational",
                     "*[System[(EventID=1116 or EventID=1117)]]",
                     250,
                     12000))
        {
            try
            {
                XDocument doc = XDocument.Parse(xml);
                XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
                var system = doc.Root?.Element(ns + "System");
                int eventId = int.TryParse(system?.Element(ns + "EventID")?.Value, out int id)
                    ? id
                    : 0;

                var data = EventData(doc, ns);

                string threatName =
                    FirstNonEmpty(
                        GetData(data, "Threat Name"),
                        GetData(data, "ThreatName"),
                        GetData(data, "Name"));

                string path =
                    FirstNonEmpty(
                        GetData(data, "Path"),
                        GetData(data, "Process Name"),
                        GetData(data, "ProcessName"));

                string action =
                    FirstNonEmpty(
                        GetData(data, "Action Name"),
                        GetData(data, "ActionName"),
                        GetData(data, "Action"));

                string detectionOrigin =
                    FirstNonEmpty(
                        GetData(data, "Detection Origin"),
                        GetData(data, "DetectionOrigin"));

                if (string.IsNullOrWhiteSpace(threatName) &&
                    string.IsNullOrWhiteSpace(path))
                {
                    string compact = string.Join(
                        " | ",
                        data
                            .Where(x => IsUsefulDefenderField(x.Key))
                            .Select(x => x.Key + "=" + x.Value));

                    if (string.IsNullOrWhiteSpace(compact))
                        continue;

                    result.Add(new DefenderDetectionRecord
                    {
                        EventId = eventId,
                        TimeCreatedUtc = EventTime(doc, ns),
                        ThreatName = compact,
                        Path = "",
                        Action = action,
                        DetectionOrigin = detectionOrigin
                    });

                    continue;
                }

                result.Add(new DefenderDetectionRecord
                {
                    EventId = eventId,
                    TimeCreatedUtc = EventTime(doc, ns),
                    ThreatName = threatName,
                    Path = path,
                    Action = action,
                    DetectionOrigin = detectionOrigin
                });
            }
            catch
            {
            }
        }

        return result
            .OrderByDescending(x => x.TimeCreatedUtc)
            .Take(250)
            .ToList();
    }

    public static List<RecentShortcutRecord> CollectRecentShortcuts()
    {
        var result = new List<RecentShortcutRecord>();

        string recent = Environment.GetFolderPath(
            Environment.SpecialFolder.Recent);

        if (string.IsNullOrWhiteSpace(recent) || !Directory.Exists(recent))
            return result;

        object? shell = null;

        try
        {
            Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return result;

            shell = Activator.CreateInstance(shellType);
            if (shell == null) return result;

            foreach (string link in Directory
                         .EnumerateFiles(recent, "*.lnk", SearchOption.TopDirectoryOnly)
                         .OrderByDescending(SafeLastWriteUtc)
                         .Take(600))
            {
                try
                {
                    object? shortcut = shellType.InvokeMember(
                        "CreateShortcut",
                        BindingFlags.InvokeMethod,
                        null,
                        shell,
                        new object[] { link });

                    if (shortcut == null) continue;

                    string target = Convert.ToString(
                        shortcut.GetType().InvokeMember(
                            "TargetPath",
                            BindingFlags.GetProperty,
                            null,
                            shortcut,
                            null)) ?? "";

                    string workingDirectory = Convert.ToString(
                        shortcut.GetType().InvokeMember(
                            "WorkingDirectory",
                            BindingFlags.GetProperty,
                            null,
                            shortcut,
                            null)) ?? "";

                    result.Add(new RecentShortcutRecord
                    {
                        ShortcutName = Path.GetFileName(link),
                        ShortcutLastWriteUtc = SafeLastWriteUtc(link),
                        TargetPath = target,
                        WorkingDirectory = workingDirectory,
                        TargetExists = SafeFileExists(target)
                    });
                }
                catch
                {
                }
            }
        }
        catch
        {
        }
        finally
        {
            if (shell != null && MarshalIsComObject(shell))
            {
                try { System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell); }
                catch { }
            }
        }

        return result;
    }

    public static List<ExtensionMismatchRecord> CollectModifiedExtensions()
    {
        string[] roots =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Downloads"),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        };

        var result = new List<ExtensionMismatchRecord>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string root in roots.Where(Directory.Exists))
        {
            foreach (string file in EnumerateFilesLimited(root, 2, 2500))
            {
                if (result.Count >= 300) return result;
                if (!seen.Add(file)) continue;

                string ext = Path.GetExtension(file);
                if (IsExpectedPeExtension(ext)) continue;

                try
                {
                    var info = new FileInfo(file);
                    if (!info.Exists || info.Length < 64 || info.Length > 500L * 1024L * 1024L)
                        continue;

                    using var stream = new FileStream(
                        file,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);

                    Span<byte> header = stackalloc byte[2];
                    if (stream.Read(header) != 2) continue;

                    bool mz = header[0] == (byte)'M' && header[1] == (byte)'Z';
                    if (!mz) continue;

                    result.Add(new ExtensionMismatchRecord
                    {
                        Name = info.Name,
                        Path = info.FullName,
                        Extension = info.Extension,
                        Size = info.Length,
                        LastWriteUtc = info.LastWriteTimeUtc,
                        Reason = "Arquivo possui cabeçalho PE/MZ mas extensão não executável."
                    });
                }
                catch
                {
                }
            }
        }

        return result;
    }

    public static List<DefenderExclusionRecord> CollectDefenderExclusions()
    {
        var result = new List<DefenderExclusionRecord>();

        string[] subkeys =
        {
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
        };

        foreach (string subkey in subkeys)
        {
            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(subkey);
                if (key == null) continue;

                foreach (string valueName in key.GetValueNames())
                {
                    if (string.IsNullOrWhiteSpace(valueName)) continue;

                    result.Add(new DefenderExclusionRecord
                    {
                        Category = subkey.Split('\\').Last(),
                        Value = valueName
                    });
                }
            }
            catch
            {
            }
        }

        return result.Take(300).ToList();
    }

    public static List<BootIntegrityRecord> CollectBootIntegrityFlags()
    {
        var result = new List<BootIntegrityRecord>();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "bcdedit.exe",
                Arguments = "/enum {current}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using Process? process = Process.Start(psi);
            if (process == null) return result;

            string output = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();

            if (!process.WaitForExit(8000))
            {
                try { process.Kill(true); } catch { }
                return result;
            }

            foreach (string raw in output.Split(
                         new[] { "\r\n", "\n" },
                         StringSplitOptions.RemoveEmptyEntries))
            {
                string line = raw.Trim();
                string lower = line.ToLowerInvariant();

                if (!lower.Contains("testsigning") &&
                    !lower.Contains("nointegritychecks") &&
                    !Regex.IsMatch(lower, @"^debug\s+"))
                {
                    continue;
                }

                string[] parts = Regex.Split(line, @"\s{2,}");
                result.Add(new BootIntegrityRecord
                {
                    Setting = parts.FirstOrDefault() ?? line,
                    Value = parts.Length > 1 ? parts[^1] : "",
                    Raw = line
                });
            }
        }
        catch
        {
        }

        return result;
    }

    public static ActivityHistoryState CollectActivityHistoryState()
    {
        var result = new ActivityHistoryState();

        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\System");

            result.EnableActivityFeed = ReadDword(key, "EnableActivityFeed");
            result.PublishUserActivities = ReadDword(key, "PublishUserActivities");
            result.UploadUserActivities = ReadDword(key, "UploadUserActivities");
        }
        catch
        {
        }

        return result;
    }

    public static List<SystemTimeChangeRecord> CollectSystemTimeChanges()
    {
        var result = new List<SystemTimeChangeRecord>();

        foreach (string xml in QueryEvents(
                     "Security",
                     "*[System[(EventID=4616)]]",
                     50,
                     10000))
        {
            try
            {
                XDocument doc = XDocument.Parse(xml);
                XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
                var data = EventData(doc, ns);

                result.Add(new SystemTimeChangeRecord
                {
                    TimeCreatedUtc = EventTime(doc, ns),
                    PreviousTime = GetData(data, "PreviousTime"),
                    NewTime = GetData(data, "NewTime"),
                    ProcessName = GetData(data, "ProcessName")
                });
            }
            catch
            {
            }
        }

        return result
            .OrderByDescending(x => x.TimeCreatedUtc)
            .ToList();
    }

    public static List<VirtualDiskRecord> CollectVirtualDiskIndicators()
    {
        var result = new List<VirtualDiskRecord>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Model,Caption,DeviceID,InterfaceType,PNPDeviceID FROM Win32_DiskDrive");

            foreach (ManagementObject item in searcher.Get())
            {
                string model = Convert.ToString(item["Model"]) ?? "";
                string caption = Convert.ToString(item["Caption"]) ?? "";
                string pnp = Convert.ToString(item["PNPDeviceID"]) ?? "";
                string interfaceType = Convert.ToString(item["InterfaceType"]) ?? "";

                string combined =
                    string.Join(" ", model, caption, pnp, interfaceType)
                        .ToLowerInvariant();

                bool suspiciousVirtual =
                    combined.Contains("virtual") ||
                    combined.Contains("vhd") ||
                    combined.Contains("imdisk") ||
                    combined.Contains("osfmount") ||
                    combined.Contains("arsenal image mounter");

                if (!suspiciousVirtual) continue;

                result.Add(new VirtualDiskRecord
                {
                    Model = model,
                    Caption = caption,
                    DeviceId = Convert.ToString(item["DeviceID"]) ?? "",
                    InterfaceType = interfaceType,
                    PnpDeviceId = pnp
                });
            }
        }
        catch
        {
        }

        return result;
    }

    public static List<RustModuleRecord> CollectRustModules()
    {
        var result = new List<RustModuleRecord>();

        Process[] processes = Process.GetProcesses()
            .Where(p =>
                p.ProcessName.Equals("RustClient", StringComparison.OrdinalIgnoreCase) ||
                p.ProcessName.Equals("Rust", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        foreach (Process process in processes)
        {
            try
            {
                string? mainPath = null;
                try { mainPath = process.MainModule?.FileName; } catch { }

                string gameDirectory = !string.IsNullOrWhiteSpace(mainPath)
                    ? Path.GetDirectoryName(mainPath) ?? ""
                    : "";

                foreach (ProcessModule module in process.Modules)
                {
                    try
                    {
                        string path = module.FileName ?? "";
                        if (string.IsNullOrWhiteSpace(path)) continue;

                        (bool signed, string signer) = TrySigner(path);
                        string company = "";

                        try
                        {
                            company = FileVersionInfo
                                .GetVersionInfo(path)
                                .CompanyName ?? "";
                        }
                        catch
                        {
                        }

                        result.Add(new RustModuleRecord
                        {
                            ProcessId = process.Id,
                            ProcessName = process.ProcessName,
                            ModuleName = module.ModuleName ?? Path.GetFileName(path),
                            Path = path,
                            Signed = signed,
                            SignerSubject = signer,
                            CompanyName = company,
                            UnderGameDirectory =
                                !string.IsNullOrWhiteSpace(gameDirectory) &&
                                IsPathUnder(path, gameDirectory),
                            UnderWindows =
                                IsPathUnder(
                                    path,
                                    Environment.GetFolderPath(
                                        Environment.SpecialFolder.Windows)),
                            UnderProgramFiles =
                                IsPathUnder(
                                    path,
                                    Environment.GetFolderPath(
                                        Environment.SpecialFolder.ProgramFiles)) ||
                                IsPathUnder(
                                    path,
                                    Environment.GetFolderPath(
                                        Environment.SpecialFolder.ProgramFilesX86)),
                            UnderUserProfile =
                                IsPathUnder(
                                    path,
                                    Environment.GetFolderPath(
                                        Environment.SpecialFolder.UserProfile)),
                            UnderTemp =
                                IsPathUnder(path, Path.GetTempPath())
                        });
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }
            finally
            {
                process.Dispose();
            }
        }

        return result
            .GroupBy(
                x => $"{x.ProcessId}|{x.Path}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(1200)
            .ToList();
    }

    public static List<UsnJournalStateRecord> CollectUsnJournalState()
    {
        var result = new List<UsnJournalStateRecord>();

        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady ||
                    drive.DriveType != DriveType.Fixed ||
                    !drive.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string volume = drive.Name.TrimEnd('\\');

                var psi = new ProcessStartInfo
                {
                    FileName = "fsutil.exe",
                    Arguments = $"usn queryjournal {volume}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using Process? process = Process.Start(psi);
                if (process == null) continue;

                string stdout = process.StandardOutput.ReadToEnd();
                string stderr = process.StandardError.ReadToEnd();

                if (!process.WaitForExit(8000))
                {
                    try { process.Kill(true); } catch { }
                    continue;
                }

                result.Add(new UsnJournalStateRecord
                {
                    Volume = volume,
                    Active = process.ExitCode == 0,
                    Detail = process.ExitCode == 0
                        ? FirstLines(stdout, 12)
                        : FirstLines(stderr, 8)
                });
            }
            catch
            {
            }
        }

        return result;
    }

    private static List<string> QueryEvents(
        string logName,
        string query,
        int count,
        int timeoutMs)
    {
        var result = new List<string>();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wevtutil.exe",
                Arguments =
                    $"qe \"{logName}\" /q:\"{query}\" /f:xml /rd:true /c:{count}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using Process? process = Process.Start(psi);
            if (process == null) return result;

            string output = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();

            if (!process.WaitForExit(timeoutMs))
            {
                try { process.Kill(true); } catch { }
                return result;
            }

            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
                return result;

            foreach (Match match in Regex.Matches(
                         output,
                         @"<Event\b.*?</Event>",
                         RegexOptions.Singleline | RegexOptions.IgnoreCase))
            {
                result.Add(match.Value);
            }
        }
        catch
        {
        }

        return result;
    }

    private static Dictionary<string, string> EventData(
        XDocument doc,
        XNamespace ns)
    {
        var result = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase);

        foreach (XElement element in doc.Descendants(ns + "Data"))
        {
            string name = element.Attribute("Name")?.Value ?? "";
            if (string.IsNullOrWhiteSpace(name)) continue;

            result[name] = (element.Value ?? "").Trim();
        }

        return result;
    }

    private static DateTime EventTime(XDocument doc, XNamespace ns)
    {
        string? raw = doc.Root?
            .Element(ns + "System")?
            .Element(ns + "TimeCreated")?
            .Attribute("SystemTime")?
            .Value;

        return DateTimeOffset.TryParse(raw, out DateTimeOffset dto)
            ? dto.UtcDateTime
            : DateTime.UtcNow;
    }

    private static string GetData(
        Dictionary<string, string> data,
        string name) =>
        data.TryGetValue(name, out string? value) ? value : "";

    private static bool IsUsefulDefenderField(string name)
    {
        string lower = name.ToLowerInvariant();
        return lower.Contains("threat") ||
               lower.Contains("path") ||
               lower.Contains("action") ||
               lower.Contains("detection");
    }

    private static int? ReadDword(RegistryKey? key, string name)
    {
        if (key?.GetValue(name) is int value) return value;
        return null;
    }

    private static bool IsExpectedPeExtension(string ext)
    {
        string[] executableExtensions =
        {
            ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".efi"
        };

        return executableExtensions.Contains(
            ext,
            StringComparer.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> EnumerateFilesLimited(
        string root,
        int maxDepth,
        int maxFiles)
    {
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((root, 0));
        int yielded = 0;

        while (queue.Count > 0 && yielded < maxFiles)
        {
            (string current, int depth) = queue.Dequeue();

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(current); }
            catch { continue; }

            foreach (string file in files)
            {
                yield return file;
                yielded++;
                if (yielded >= maxFiles) yield break;
            }

            if (depth >= maxDepth) continue;

            IEnumerable<string> dirs;
            try { dirs = Directory.EnumerateDirectories(current); }
            catch { continue; }

            foreach (string dir in dirs.Take(180))
                queue.Enqueue((dir, depth + 1));
        }
    }

    private static bool SafeFileExists(string path)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(path) && File.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    private static DateTime SafeLastWriteUtc(string path)
    {
        try { return File.GetLastWriteTimeUtc(path); }
        catch { return DateTime.MinValue; }
    }

    private static (bool Signed, string Subject) TrySigner(string path)
    {
        try
        {
            X509Certificate certificate =
                X509Certificate.CreateFromSignedFile(path);

            using var cert2 = new X509Certificate2(certificate);
            return (true, cert2.Subject ?? "");
        }
        catch
        {
            return (false, "");
        }
    }

    private static bool IsPathUnder(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        try
        {
            string fullPath = Path.GetFullPath(path)
                .TrimEnd(Path.DirectorySeparatorChar) +
                Path.DirectorySeparatorChar;

            string fullRoot = Path.GetFullPath(root)
                .TrimEnd(Path.DirectorySeparatorChar) +
                Path.DirectorySeparatorChar;

            return fullPath.StartsWith(
                fullRoot,
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool MarshalIsComObject(object value)
    {
        try
        {
            return System.Runtime.InteropServices.Marshal.IsComObject(value);
        }
        catch
        {
            return false;
        }
    }

    private static string FirstNonEmpty(params string[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";

    private static string FirstLines(string text, int count) =>
        string.Join(
            "\n",
            (text ?? "")
                .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Take(count));
}

internal sealed class ProcessCreationRecord
{
    public DateTime TimeCreatedUtc { get; set; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    public string ParentProcessName { get; set; } = "";
    public string ParentProcessPath { get; set; } = "";
}

internal sealed class DefenderDetectionRecord
{
    public int EventId { get; set; }
    public DateTime TimeCreatedUtc { get; set; }
    public string ThreatName { get; set; } = "";
    public string Path { get; set; } = "";
    public string Action { get; set; } = "";
    public string DetectionOrigin { get; set; } = "";
}

internal sealed class RecentShortcutRecord
{
    public string ShortcutName { get; set; } = "";
    public DateTime ShortcutLastWriteUtc { get; set; }
    public string TargetPath { get; set; } = "";
    public string WorkingDirectory { get; set; } = "";
    public bool TargetExists { get; set; }
}

internal sealed class ExtensionMismatchRecord
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Extension { get; set; } = "";
    public long Size { get; set; }
    public DateTime LastWriteUtc { get; set; }
    public string Reason { get; set; } = "";
}

internal sealed class DefenderExclusionRecord
{
    public string Category { get; set; } = "";
    public string Value { get; set; } = "";
}

internal sealed class BootIntegrityRecord
{
    public string Setting { get; set; } = "";
    public string Value { get; set; } = "";
    public string Raw { get; set; } = "";
}

internal sealed class ActivityHistoryState
{
    public int? EnableActivityFeed { get; set; }
    public int? PublishUserActivities { get; set; }
    public int? UploadUserActivities { get; set; }
}

internal sealed class SystemTimeChangeRecord
{
    public DateTime TimeCreatedUtc { get; set; }
    public string PreviousTime { get; set; } = "";
    public string NewTime { get; set; } = "";
    public string ProcessName { get; set; } = "";
}

internal sealed class VirtualDiskRecord
{
    public string Model { get; set; } = "";
    public string Caption { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string InterfaceType { get; set; } = "";
    public string PnpDeviceId { get; set; } = "";
}

internal sealed class RustModuleRecord
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string ModuleName { get; set; } = "";
    public string Path { get; set; } = "";
    public bool Signed { get; set; }
    public string SignerSubject { get; set; } = "";
    public string CompanyName { get; set; } = "";
    public bool UnderGameDirectory { get; set; }
    public bool UnderWindows { get; set; }
    public bool UnderProgramFiles { get; set; }
    public bool UnderUserProfile { get; set; }
    public bool UnderTemp { get; set; }
}

internal sealed class UsnJournalStateRecord
{
    public string Volume { get; set; } = "";
    public bool Active { get; set; }
    public string Detail { get; set; } = "";
}
