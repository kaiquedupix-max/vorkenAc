using Microsoft.Win32;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Vorken.Agent;

internal static class AutorunIntegrityCollector
{
    public static List<AutorunIntegrityRecord> Collect()
    {
        var result = new List<AutorunIntegrityRecord>();

        CollectRunKey(
            Microsoft.Win32.Registry.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU Run",
            result);

        CollectRunKey(
            Microsoft.Win32.Registry.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU RunOnce",
            result);

        CollectRunKey(
            Microsoft.Win32.Registry.LocalMachine,
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM Run",
            result);

        CollectRunKey(
            Microsoft.Win32.Registry.LocalMachine,
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM RunOnce",
            result);

        CollectStartupFolder(result);
        CollectScheduledTasks(result);

        return result
            .GroupBy(
                x => $"{x.Source}|{x.Name}|{x.Command}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(2500)
            .ToList();
    }

    private static void CollectRunKey(
        RegistryKey hive,
        string subKey,
        string source,
        List<AutorunIntegrityRecord> result)
    {
        try
        {
            using RegistryKey? key = hive.OpenSubKey(subKey);
            if (key == null) return;

            foreach (string name in key.GetValueNames())
            {
                string command =
                    Convert.ToString(key.GetValue(name)) ?? "";

                AddRecord(
                    result,
                    source,
                    name,
                    command,
                    enabled: true);
            }
        }
        catch
        {
        }
    }

    private static void CollectStartupFolder(
        List<AutorunIntegrityRecord> result)
    {
        string[] folders =
        {
            Environment.GetFolderPath(
                Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonStartup)
        };

        foreach (string folder in folders.Distinct(
                     StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(folder))
                continue;

            IEnumerable<string> files;

            try
            {
                files = Directory.EnumerateFiles(folder);
            }
            catch
            {
                continue;
            }

            foreach (string file in files.Take(600))
            {
                AddRecord(
                    result,
                    "Startup Folder",
                    Path.GetFileName(file),
                    file,
                    enabled: true);
            }
        }
    }

    private static void CollectScheduledTasks(
        List<AutorunIntegrityRecord> result)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = "/query /fo CSV /v /nh",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using Process? process = Process.Start(psi);
            if (process == null)
                return;

            string output = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();

            if (!process.WaitForExit(20000))
            {
                try { process.Kill(true); } catch { }
                return;
            }

            if (process.ExitCode != 0)
                return;

            foreach (string line in output.Split(
                         new[] { "\r\n", "\n" },
                         StringSplitOptions.RemoveEmptyEntries)
                     .Take(2500))
            {
                List<string> fields = ParseCsv(line);

                if (fields.Count < 9)
                    continue;

                string taskName = fields.ElementAtOrDefault(1) ?? "";
                string status = fields.ElementAtOrDefault(3) ?? "";
                string runAs = fields.ElementAtOrDefault(7) ?? "";
                string taskToRun =
                    fields.FirstOrDefault(x =>
                        x.Contains(".exe", StringComparison.OrdinalIgnoreCase) ||
                        x.Contains(".bat", StringComparison.OrdinalIgnoreCase) ||
                        x.Contains(".cmd", StringComparison.OrdinalIgnoreCase) ||
                        x.Contains(".ps1", StringComparison.OrdinalIgnoreCase)) ?? "";

                if (string.IsNullOrWhiteSpace(taskToRun))
                    continue;

                AddRecord(
                    result,
                    "Scheduled Task",
                    taskName,
                    taskToRun,
                    !status.Equals(
                        "Disabled",
                        StringComparison.OrdinalIgnoreCase),
                    runAs);
            }
        }
        catch
        {
        }
    }

    private static void AddRecord(
        List<AutorunIntegrityRecord> result,
        string source,
        string name,
        string command,
        bool enabled,
        string runAs = "")
    {
        string executable = ExtractExecutablePath(command);

        bool exists =
            !string.IsNullOrWhiteSpace(executable) &&
            File.Exists(executable);

        bool signed = false;
        string signer = "";

        if (exists)
        {
            (signed, signer) =
                AuthenticodeVerifier.Verify(executable);
        }

        bool userWritable =
            IsUserWritablePath(executable);

        bool suspicious =
            enabled &&
            (
                userWritable ||
                (
                    exists &&
                    !signed &&
                    Path.GetExtension(executable)
                        .Equals(
                            ".exe",
                            StringComparison.OrdinalIgnoreCase)
                )
            );

        result.Add(new AutorunIntegrityRecord
        {
            Source = source,
            Name = name,
            Command = command,
            ExecutablePath = executable,
            FileExists = exists,
            Signed = signed,
            SignerSubject = signer,
            UserWritablePath = userWritable,
            Enabled = enabled,
            RunAs = runAs,
            Suspicious = suspicious
        });
    }

    private static string ExtractExecutablePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
            return "";

        string expanded =
            Environment.ExpandEnvironmentVariables(command.Trim());

        if (expanded.StartsWith('"'))
        {
            int end = expanded.IndexOf('"', 1);
            if (end > 1)
                return expanded[1..end];
        }

        Match match = Regex.Match(
            expanded,
            @"^[^\r\n]*?\.(exe|com|bat|cmd|ps1|scr)",
            RegexOptions.IgnoreCase);

        return match.Success
            ? match.Value.Trim().Trim('"')
            : "";
    }

    private static bool IsUserWritablePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        string normalized = path
            .Replace('/', '\\')
            .ToLowerInvariant();

        string user = Environment
            .GetFolderPath(
                Environment.SpecialFolder.UserProfile)
            .Replace('/', '\\')
            .ToLowerInvariant();

        string temp = Path
            .GetTempPath()
            .Replace('/', '\\')
            .ToLowerInvariant();

        return
            (
                !string.IsNullOrWhiteSpace(user) &&
                normalized.StartsWith(user)
            ) ||
            (
                !string.IsNullOrWhiteSpace(temp) &&
                normalized.StartsWith(temp)
            );
    }

    private static List<string> ParseCsv(string line)
    {
        var result = new List<string>();

        foreach (Match match in Regex.Matches(
                     line,
                     "(?:^|,)(?:\"((?:\"\"|[^\"])*)\"|([^,]*))"))
        {
            string value = match.Groups[1].Success
                ? match.Groups[1].Value.Replace("\"\"", "\"")
                : match.Groups[2].Value;

            result.Add(value);
        }

        return result;
    }
}

internal sealed class AutorunIntegrityRecord
{
    public string Source { get; set; } = "";
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public string ExecutablePath { get; set; } = "";
    public bool FileExists { get; set; }
    public bool Signed { get; set; }
    public string SignerSubject { get; set; } = "";
    public bool UserWritablePath { get; set; }
    public bool Enabled { get; set; }
    public string RunAs { get; set; } = "";
    public bool Suspicious { get; set; }
}
