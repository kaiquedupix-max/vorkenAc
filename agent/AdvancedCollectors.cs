using Microsoft.Win32;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Vorken.Agent;

/// <summary>
/// Read-only Windows forensic collectors inspired by public DFIR techniques.
/// These collectors intentionally avoid passwords, browser cookies, messages,
/// document contents and unrestricted PowerShell history collection.
/// </summary>
internal static class AdvancedCollectors
{
    public static List<BamRecord> CollectBam()
    {
        var result = new List<BamRecord>();
        using RegistryKey? root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings");

        if (root == null)
        {
            using RegistryKey? legacy = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\bam\UserSettings");
            return legacy == null ? result : ReadBamRoot(legacy);
        }

        return ReadBamRoot(root);
    }

    private static List<BamRecord> ReadBamRoot(RegistryKey root)
    {
        var result = new List<BamRecord>();

        foreach (string sid in root.GetSubKeyNames())
        {
            using RegistryKey? sidKey = root.OpenSubKey(sid);
            if (sidKey == null) continue;

            foreach (string valueName in sidKey.GetValueNames())
            {
                if (string.IsNullOrWhiteSpace(valueName) ||
                    valueName.StartsWith("Version", StringComparison.OrdinalIgnoreCase) ||
                    valueName.StartsWith("SequenceNumber", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                object? raw = sidKey.GetValue(valueName);
                DateTime? lastExecutionUtc = null;

                if (raw is byte[] bytes && bytes.Length >= 8)
                {
                    try
                    {
                        long fileTime = BitConverter.ToInt64(bytes, 0);
                        if (fileTime > 0)
                            lastExecutionUtc = DateTime.FromFileTimeUtc(fileTime);
                    }
                    catch
                    {
                    }
                }

                result.Add(new BamRecord
                {
                    Sid = sid,
                    Path = valueName,
                    LastExecutionUtc = lastExecutionUtc,
                    FileExists = SafeFileExists(valueName)
                });
            }
        }

        return result
            .OrderByDescending(x => x.LastExecutionUtc ?? DateTime.MinValue)
            .Take(5000)
            .ToList();
    }

    public static List<UserAssistRecord> CollectUserAssist()
    {
        var result = new List<UserAssistRecord>();
        using RegistryKey? root = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");

        if (root == null) return result;

        foreach (string guid in root.GetSubKeyNames())
        {
            using RegistryKey? countKey = root.OpenSubKey(guid + @"\Count");
            if (countKey == null) continue;

            foreach (string encodedName in countKey.GetValueNames())
            {
                string decoded = Rot13(encodedName);
                object? raw = countKey.GetValue(encodedName);

                DateTime? lastExecutionUtc = null;
                int? runCount = null;
                int dataLength = 0;

                if (raw is byte[] bytes)
                {
                    dataLength = bytes.Length;

                    // Windows 7+ UserAssist Count values are normally 72 bytes.
                    // Run count is stored at offset 4 and the last execution
                    // FILETIME at offset 60. Parse defensively because older
                    // Windows builds may use a different layout.
                    if (bytes.Length >= 8)
                    {
                        try
                        {
                            int parsedRunCount =
                                BitConverter.ToInt32(bytes, 4);

                            if (parsedRunCount >= 0)
                                runCount = parsedRunCount;
                        }
                        catch
                        {
                        }
                    }

                    if (bytes.Length >= 68)
                    {
                        try
                        {
                            long fileTime =
                                BitConverter.ToInt64(bytes, 60);

                            if (fileTime > 0)
                            {
                                DateTime parsed =
                                    DateTime.FromFileTimeUtc(fileTime);

                                if (
                                    parsed.Year >= 2000 &&
                                    parsed <= DateTime.UtcNow.AddDays(2)
                                )
                                {
                                    lastExecutionUtc = parsed;
                                }
                            }
                        }
                        catch
                        {
                        }
                    }
                }

                result.Add(new UserAssistRecord
                {
                    Guid = guid,
                    EncodedName = encodedName,
                    DecodedName = decoded,
                    DataLength = dataLength,
                    RunCount = runCount,
                    LastExecutionUtc = lastExecutionUtc
                });
            }
        }

        return result.Take(5000).ToList();
    }

    public static List<MuiCacheRecord> CollectMuiCache()
    {
        var result = new List<MuiCacheRecord>();
        string[] paths =
        {
            @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            @"Software\Microsoft\Windows\ShellNoRoam\MUICache"
        };

        foreach (string registryPath in paths)
        {
            using RegistryKey? key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(registryPath);
            if (key == null) continue;

            foreach (string name in key.GetValueNames())
            {
                if (string.IsNullOrWhiteSpace(name)) continue;

                result.Add(new MuiCacheRecord
                {
                    RegistryPath = registryPath,
                    Path = name,
                    DisplayName = Convert.ToString(key.GetValue(name)) ?? "",
                    FileExists = SafeFileExists(name)
                });
            }
        }

        return result
            .GroupBy(x => x.RegistryPath + "|" + x.Path, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(5000)
            .ToList();
    }

    public static List<PcaRecord> CollectPcaStore()
    {
        var result = new List<PcaRecord>();
        string[] paths =
        {
            @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
            @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted"
        };

        foreach (string registryPath in paths)
        {
            using RegistryKey? key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(registryPath);
            if (key == null) continue;

            foreach (string name in key.GetValueNames())
            {
                if (string.IsNullOrWhiteSpace(name)) continue;

                result.Add(new PcaRecord
                {
                    Source = registryPath.EndsWith("Store", StringComparison.OrdinalIgnoreCase)
                        ? "PCA Store"
                        : "PCA Persisted",
                    Path = name,
                    FileExists = SafeFileExists(name)
                });
            }
        }

        return result
            .GroupBy(x => x.Source + "|" + x.Path, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(5000)
            .ToList();
    }

    public static List<SetupApiUsbRecord> CollectSetupApiUsb()
    {
        var result = new List<SetupApiUsbRecord>();
        string logPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "INF",
            "setupapi.dev.log");

        if (!File.Exists(logPath)) return result;

        int lineNumber = 0;
        string currentSection = "";
        DateTime? currentSectionUtc = null;

        foreach (string rawLine in File.ReadLines(logPath))
        {
            lineNumber++;
            string line = rawLine.Trim();

            if (line.StartsWith(">>> [", StringComparison.Ordinal))
            {
                currentSection = line.Length > 300 ? line[..300] : line;
                currentSectionUtc = null;
                continue;
            }

            if (line.Contains("Section start", StringComparison.OrdinalIgnoreCase))
            {
                string value = line[(line.IndexOf("Section start", StringComparison.OrdinalIgnoreCase) + "Section start".Length)..].Trim();
                if (DateTime.TryParse(value, out DateTime parsed))
                    currentSectionUtc = parsed.ToUniversalTime();
            }

            bool usb =
                line.Contains("USBSTOR\\", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("USB\\VID_", StringComparison.OrdinalIgnoreCase) ||
                (line.Contains("VID_", StringComparison.OrdinalIgnoreCase) &&
                 line.Contains("PID_", StringComparison.OrdinalIgnoreCase));

            if (!usb) continue;

            result.Add(new SetupApiUsbRecord
            {
                LineNumber = lineNumber,
                Section = currentSection,
                SectionTimeUtc = currentSectionUtc,
                Evidence = line.Length > 600 ? line[..600] : line
            });

            if (result.Count >= 1200) break;
        }

        return result;
    }

    public static List<PowerShellRuleHit> CollectPowerShellRuleHits(List<DetectionRule> rules)
    {
        var patterns = rules
            .Where(x => string.Equals(x.Type, "powershell_contains", StringComparison.OrdinalIgnoreCase))
            .Select(x => new { x.Id, x.Name, Pattern = (x.Pattern ?? "").Trim() })
            .Where(x => x.Pattern.Length >= 3)
            .ToList();

        // Privacy-by-default: never upload general PowerShell history.
        // Only upload lines that match an administrator-defined detection rule.
        if (patterns.Count == 0) return new List<PowerShellRuleHit>();

        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        candidates.Add(Path.Combine(
            appData,
            "Microsoft",
            "Windows",
            "PowerShell",
            "PSReadLine",
            "ConsoleHost_history.txt"));

        candidates.Add(Path.Combine(
            userProfile,
            "AppData",
            "Roaming",
            "Microsoft",
            "Windows",
            "PowerShell",
            "PSReadLine",
            "Visual Studio Code Host_history.txt"));

        var result = new List<PowerShellRuleHit>();

        foreach (string file in candidates)
        {
            if (!File.Exists(file)) continue;

            int lineNumber = 0;
            foreach (string raw in File.ReadLines(file))
            {
                lineNumber++;
                string line = raw.Trim();
                if (line.Length == 0) continue;

                foreach (var rule in patterns)
                {
                    if (!line.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    result.Add(new PowerShellRuleHit
                    {
                        RuleId = rule.Id,
                        RuleName = rule.Name,
                        Pattern = rule.Pattern,
                        SourceFile = Path.GetFileName(file),
                        LineNumber = lineNumber,
                        MatchedLine = line.Length > 500 ? line[..500] : line
                    });

                    if (result.Count >= 500) return result;
                }
            }
        }

        return result;
    }

    public static SystemArtifactRecord CollectSystemArtifactState()
    {
        var result = new SystemArtifactRecord
        {
            PrefetchDirectoryExists = Directory.Exists(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "Prefetch")),
            AmcacheExists = File.Exists(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "AppCompat",
                "Programs",
                "Amcache.hve")),
            SetupApiLogExists = File.Exists(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "INF",
                "setupapi.dev.log"))
        };

        try
        {
            using RegistryKey? key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
            result.EnablePrefetcher = key?.GetValue("EnablePrefetcher") is int value ? value : null;
        }
        catch
        {
        }

        try
        {
            using RegistryKey? bamKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\bam");
            result.BamStart = bamKey?.GetValue("Start") is int start ? start : null;
        }
        catch
        {
        }

        return result;
    }

    public static List<PrefetchIntegrityRecord> CollectPrefetchIntegrity()
    {
        var result = new List<PrefetchIntegrityRecord>();
        string directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Prefetch");

        if (!Directory.Exists(directory)) return result;

        var byHash = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (string file in Directory.EnumerateFiles(directory, "*.pf", SearchOption.TopDirectoryOnly).Take(5000))
        {
            try
            {
                var info = new FileInfo(file);
                string? hash = TrySha256(file);

                if (!string.IsNullOrWhiteSpace(hash))
                {
                    if (!byHash.TryGetValue(hash, out List<string>? names))
                    {
                        names = new List<string>();
                        byHash[hash] = names;
                    }
                    names.Add(info.Name);
                }

                if (info.IsReadOnly)
                {
                    result.Add(new PrefetchIntegrityRecord
                    {
                        Kind = "read_only",
                        Name = info.Name,
                        Detail = "Prefetch marcado como somente leitura.",
                        Sha256 = hash,
                        LastWriteUtc = info.LastWriteTimeUtc
                    });
                }
            }
            catch
            {
            }
        }

        foreach (var pair in byHash.Where(x => x.Value.Count > 1))
        {
            result.Add(new PrefetchIntegrityRecord
            {
                Kind = "duplicate_hash",
                Name = string.Join(", ", pair.Value.Take(12)),
                Detail = "Múltiplos arquivos Prefetch possuem o mesmo SHA-256.",
                Sha256 = pair.Key
            });
        }

        return result.Take(500).ToList();
    }

    public static List<VolumeRecord> CollectVolumesWithoutDriveLetter()
    {
        var result = new List<VolumeRecord>();

        using var searcher = new ManagementObjectSearcher(
            "SELECT DeviceID,DriveLetter,Label,FileSystem,Capacity,BootVolume,SystemVolume FROM Win32_Volume");

        foreach (ManagementObject item in searcher.Get())
        {
            string driveLetter = Convert.ToString(item["DriveLetter"]) ?? "";
            if (!string.IsNullOrWhiteSpace(driveLetter)) continue;

            bool boot = Convert.ToBoolean(item["BootVolume"] ?? false);
            bool system = Convert.ToBoolean(item["SystemVolume"] ?? false);

            result.Add(new VolumeRecord
            {
                DeviceId = Convert.ToString(item["DeviceID"]) ?? "",
                Label = Convert.ToString(item["Label"]) ?? "",
                FileSystem = Convert.ToString(item["FileSystem"]) ?? "",
                Capacity = item["Capacity"] is null ? null : Convert.ToUInt64(item["Capacity"]),
                BootVolume = boot,
                SystemVolume = system,
                ExpectedSystemVolume = boot || system
            });
        }

        return result.Take(100).ToList();
    }

    public static List<EventLogSignalRecord> CollectRecentLogClearSignals()
    {
        var result = new List<EventLogSignalRecord>();
        ReadWevtutil(
            "System",
            "*[System[(EventID=104) and TimeCreated[timediff(@SystemTime) <= 86400000]]]",
            "System log clear (Event ID 104)",
            result);

        ReadWevtutil(
            "Security",
            "*[System[(EventID=1102) and TimeCreated[timediff(@SystemTime) <= 86400000]]]",
            "Security audit log clear (Event ID 1102)",
            result);

        return result;
    }

    private static void ReadWevtutil(
        string channel,
        string query,
        string signal,
        List<EventLogSignalRecord> result)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "wevtutil.exe",
                Arguments = $"qe {channel} /q:\"{query}\" /f:text /rd:true /c:10",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = System.Diagnostics.Process.Start(psi);
            if (process == null) return;

            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();

            if (!process.WaitForExit(8000))
            {
                try { process.Kill(true); } catch { }
                return;
            }

            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
                return;

            string normalized = output.Trim();
            if (normalized.Length > 12000) normalized = normalized[..12000];

            result.Add(new EventLogSignalRecord
            {
                Channel = channel,
                Signal = signal,
                WindowHours = 24,
                Evidence = normalized
            });
        }
        catch
        {
        }
    }

    private static string? TrySha256(string path)
    {
        try
        {
            using FileStream stream = new(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    private static bool SafeFileExists(string value)
    {
        try
        {
            string expanded = Environment.ExpandEnvironmentVariables(value.Trim('"'));

            if (expanded.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            {
                string? resolved = ResolveNativePath(expanded);
                return !string.IsNullOrWhiteSpace(resolved) && File.Exists(resolved);
            }

            return File.Exists(expanded);
        }
        catch
        {
            return false;
        }
    }

    private static string? ResolveNativePath(string nativePath)
    {
        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            string driveLetter = drive.Name.TrimEnd('\\');
            string? devicePath = QueryDevice(driveLetter);
            if (string.IsNullOrWhiteSpace(devicePath)) continue;

            if (!nativePath.StartsWith(devicePath, StringComparison.OrdinalIgnoreCase))
                continue;

            string suffix = nativePath[devicePath.Length..].TrimStart('\\');
            return driveLetter + "\\" + suffix;
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(
        string? lpDeviceName,
        StringBuilder lpTargetPath,
        int ucchMax);

    private static string Rot13(string value)
    {
        var chars = value.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c is >= 'a' and <= 'z')
                chars[i] = (char)('a' + ((c - 'a' + 13) % 26));
            else if (c is >= 'A' and <= 'Z')
                chars[i] = (char)('A' + ((c - 'A' + 13) % 26));
        }
        return new string(chars);
    }
}

internal sealed class BamRecord
{
    public string Sid { get; set; } = "";
    public string Path { get; set; } = "";
    public DateTime? LastExecutionUtc { get; set; }
    public bool FileExists { get; set; }
}

internal sealed class UserAssistRecord
{
    public string Guid { get; set; } = "";
    public string EncodedName { get; set; } = "";
    public string DecodedName { get; set; } = "";
    public int DataLength { get; set; }
    public int? RunCount { get; set; }
    public DateTime? LastExecutionUtc { get; set; }
}

internal sealed class MuiCacheRecord
{
    public string RegistryPath { get; set; } = "";
    public string Path { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public bool FileExists { get; set; }
}

internal sealed class PcaRecord
{
    public string Source { get; set; } = "";
    public string Path { get; set; } = "";
    public bool FileExists { get; set; }
}

internal sealed class SetupApiUsbRecord
{
    public int LineNumber { get; set; }
    public string Section { get; set; } = "";
    public DateTime? SectionTimeUtc { get; set; }
    public string Evidence { get; set; } = "";
}

internal sealed class PowerShellRuleHit
{
    public long RuleId { get; set; }
    public string RuleName { get; set; } = "";
    public string Pattern { get; set; } = "";
    public string SourceFile { get; set; } = "";
    public int LineNumber { get; set; }
    public string MatchedLine { get; set; } = "";
}

internal sealed class SystemArtifactRecord
{
    public bool PrefetchDirectoryExists { get; set; }
    public int? EnablePrefetcher { get; set; }
    public bool AmcacheExists { get; set; }
    public bool SetupApiLogExists { get; set; }
    public int? BamStart { get; set; }
}

internal sealed class PrefetchIntegrityRecord
{
    public string Kind { get; set; } = "";
    public string Name { get; set; } = "";
    public string Detail { get; set; } = "";
    public string? Sha256 { get; set; }
    public DateTime? LastWriteUtc { get; set; }
}

internal sealed class VolumeRecord
{
    public string DeviceId { get; set; } = "";
    public string Label { get; set; } = "";
    public string FileSystem { get; set; } = "";
    public ulong? Capacity { get; set; }
    public bool BootVolume { get; set; }
    public bool SystemVolume { get; set; }
    public bool ExpectedSystemVolume { get; set; }
}

internal sealed class EventLogSignalRecord
{
    public string Channel { get; set; } = "";
    public string Signal { get; set; } = "";
    public int WindowHours { get; set; }
    public string Evidence { get; set; } = "";
}
