using Microsoft.Win32;
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
        using RegistryKey? root = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings");

        if (root == null)
        {
            using RegistryKey? legacy = Registry.LocalMachine.OpenSubKey(
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
        using RegistryKey? root = Registry.CurrentUser.OpenSubKey(
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

                result.Add(new UserAssistRecord
                {
                    Guid = guid,
                    EncodedName = encodedName,
                    DecodedName = decoded,
                    DataLength = raw is byte[] bytes ? bytes.Length : 0
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
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(registryPath);
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
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(registryPath);
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
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
            result.EnablePrefetcher = key?.GetValue("EnablePrefetcher") is int value ? value : null;
        }
        catch
        {
        }

        return result;
    }

    private static bool SafeFileExists(string value)
    {
        try
        {
            string expanded = Environment.ExpandEnvironmentVariables(value.Trim('"'));
            if (expanded.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                return false;
            return File.Exists(expanded);
        }
        catch
        {
            return false;
        }
    }

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
}
