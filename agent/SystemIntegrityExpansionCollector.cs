using Microsoft.Win32;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Vorken.Agent;

internal static class SystemIntegrityExpansionCollector
{
    private static readonly string[] ImportantServices =
    {
        "EventLog",
        "DPS",
        "PcaSvc",
        "DiagTrack",
        "SysMain",
        "WSearch",
        "WinDefend"
    };

    public static List<SystemIntegrityExpansionRecord> Collect()
    {
        var result = new List<SystemIntegrityExpansionRecord>();

        CollectSecureBoot(result);
        CollectBcd(result);
        CollectServiceState(result);
        CollectServiceEvents(result);
        CollectSrumState(result);
        CollectPrefetchState(result);

        return result
            .GroupBy(
                x => $"{x.Kind}|{x.Name}|{x.TimestampUtc:O}|{x.Detail}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(1200)
            .ToList();
    }

    private static void CollectSecureBoot(
        List<SystemIntegrityExpansionRecord> result)
    {
        try
        {
            using RegistryKey? key =
                Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");

            object? raw = key?.GetValue(
                "UEFISecureBootEnabled");

            int? value = raw is int number
                ? number
                : null;

            result.Add(new SystemIntegrityExpansionRecord
            {
                Kind = "secure_boot",
                Name = "UEFI Secure Boot",
                SeverityHint =
                    value == 0
                        ? "medium"
                        : "info",
                Detail =
                    value is null
                        ? "Estado não disponível."
                        : value == 1
                            ? "Ativado"
                            : "Desativado"
            });
        }
        catch
        {
        }
    }

    private static void CollectBcd(
        List<SystemIntegrityExpansionRecord> result)
    {
        string current = Run(
            "bcdedit.exe",
            "/enum {current}",
            10000);

        if (!string.IsNullOrWhiteSpace(current))
        {
            foreach (string raw in current.Split(
                         new[] { "\r\n", "\n" },
                         StringSplitOptions.RemoveEmptyEntries))
            {
                string line = raw.Trim();
                string lower = line.ToLowerInvariant();

                string severity = "info";
                bool interesting = false;

                if (
                    lower.Contains("testsigning") &&
                    !lower.EndsWith(" no"))
                {
                    severity = "high";
                    interesting = true;
                }

                if (
                    lower.Contains("nointegritychecks") &&
                    !lower.EndsWith(" no"))
                {
                    severity = "high";
                    interesting = true;
                }

                if (
                    Regex.IsMatch(
                        lower,
                        @"^debug\s+(yes|on|true)"))
                {
                    severity = "high";
                    interesting = true;
                }

                if (
                    lower.Contains("hypervisorlaunchtype") ||
                    lower.Contains("bootmenupolicy") ||
                    lower.Contains("nx ") ||
                    lower.StartsWith("nx "))
                {
                    interesting = true;
                }

                if (!interesting)
                    continue;

                result.Add(new SystemIntegrityExpansionRecord
                {
                    Kind = "bcd",
                    Name = "BCD Current",
                    SeverityHint = severity,
                    Detail = line
                });
            }
        }

        string firmware = Run(
            "bcdedit.exe",
            "/enum firmware",
            12000);

        if (!string.IsNullOrWhiteSpace(firmware))
        {
            string clipped =
                firmware.Length > 24000
                    ? firmware[..24000]
                    : firmware;

            result.Add(new SystemIntegrityExpansionRecord
            {
                Kind = "efi_entries",
                Name = "Entradas EFI / firmware",
                SeverityHint = "info",
                Detail = clipped
            });
        }
    }

    private static void CollectServiceState(
        List<SystemIntegrityExpansionRecord> result)
    {
        foreach (string serviceName in ImportantServices)
        {
            try
            {
                using RegistryKey? key =
                    Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\" +
                        serviceName);

                int? start =
                    key?.GetValue("Start") is int value
                        ? value
                        : null;

                string imagePath =
                    Convert.ToString(
                        key?.GetValue("ImagePath")) ?? "";

                string severity =
                    start == 4 &&
                    serviceName is
                        "EventLog" or
                        "DPS" or
                        "PcaSvc"
                        ? "high"
                        : "info";

                result.Add(new SystemIntegrityExpansionRecord
                {
                    Kind = "service_state",
                    Name = serviceName,
                    SeverityHint = severity,
                    Detail =
                        $"Start={start?.ToString() ?? "?"} | ImagePath={imagePath}"
                });
            }
            catch
            {
            }
        }
    }

    private static void CollectServiceEvents(
        List<SystemIntegrityExpansionRecord> result)
    {
        string query =
            "*[System[(EventID=7036 or EventID=7040) " +
            "and TimeCreated[timediff(@SystemTime) <= 172800000]]]";

        foreach (string xml in QueryEvents(
                     "System",
                     query,
                     250))
        {
            try
            {
                XDocument doc =
                    XDocument.Parse(xml);

                XNamespace ns =
                    "http://schemas.microsoft.com/win/2004/08/events/event";

                string provider =
                    doc.Root?
                        .Element(ns + "System")?
                        .Element(ns + "Provider")?
                        .Attribute("Name")?
                        .Value ?? "";

                if (
                    !provider.Contains(
                        "Service Control Manager",
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                int eventId =
                    int.TryParse(
                        doc.Root?
                            .Element(ns + "System")?
                            .Element(ns + "EventID")?
                            .Value,
                        out int parsed)
                            ? parsed
                            : 0;

                DateTime? time =
                    TryEventTime(
                        doc,
                        ns);

                string message =
                    string.Join(
                        " | ",
                        doc.Descendants(ns + "Data")
                            .Select(x => x.Value)
                            .Where(x =>
                                !string.IsNullOrWhiteSpace(x)));

                bool important =
                    ImportantServices.Any(name =>
                        message.Contains(
                            name,
                            StringComparison.OrdinalIgnoreCase));

                if (!important)
                    continue;

                result.Add(new SystemIntegrityExpansionRecord
                {
                    Kind =
                        eventId == 7040
                            ? "service_start_type_change"
                            : "service_state_change",
                    Name = "Service Control Manager",
                    SeverityHint =
                        eventId == 7040
                            ? "medium"
                            : "info",
                    TimestampUtc = time,
                    Detail = message.Length > 2500
                        ? message[..2500]
                        : message
                });
            }
            catch
            {
            }
        }
    }

    private static void CollectSrumState(
        List<SystemIntegrityExpansionRecord> result)
    {
        string windows =
            Environment.GetFolderPath(
                Environment.SpecialFolder.Windows);

        string path = Path.Combine(
            windows,
            "System32",
            "sru",
            "SRUDB.dat");

        try
        {
            bool exists =
                File.Exists(path);

            result.Add(new SystemIntegrityExpansionRecord
            {
                Kind = "srum_state",
                Name = "SRUDB.dat",
                SeverityHint =
                    exists
                        ? "info"
                        : "medium",
                TimestampUtc =
                    exists
                        ? File.GetLastWriteTimeUtc(path)
                        : null,
                Detail =
                    exists
                        ? path
                        : "Banco SRUM não localizado."
            });
        }
        catch
        {
        }
    }

    private static void CollectPrefetchState(
        List<SystemIntegrityExpansionRecord> result)
    {
        string windows =
            Environment.GetFolderPath(
                Environment.SpecialFolder.Windows);

        string directory =
            Path.Combine(
                windows,
                "Prefetch");

        try
        {
            int count =
                Directory.Exists(directory)
                    ? Directory.EnumerateFiles(
                            directory,
                            "*.pf",
                            SearchOption.TopDirectoryOnly)
                        .Take(5000)
                        .Count()
                    : 0;

            result.Add(new SystemIntegrityExpansionRecord
            {
                Kind = "prefetch_state",
                Name = "Windows Prefetch",
                SeverityHint =
                    count == 0
                        ? "medium"
                        : "info",
                Detail =
                    Directory.Exists(directory)
                        ? $"Arquivos PF atuais: {count}"
                        : "Diretório Prefetch não localizado."
            });
        }
        catch
        {
        }
    }

    private static IEnumerable<string> QueryEvents(
        string log,
        string query,
        int count)
    {
        string output = Run(
            "wevtutil.exe",
            $"qe \"{log}\" /q:\"{query}\" /f:xml /rd:true /c:{count}",
            16000);

        if (string.IsNullOrWhiteSpace(output))
            yield break;

        foreach (Match match in Regex.Matches(
                     output,
                     @"<Event\b.*?</Event>",
                     RegexOptions.Singleline |
                     RegexOptions.IgnoreCase))
        {
            yield return match.Value;
        }
    }

    private static DateTime? TryEventTime(
        XDocument doc,
        XNamespace ns)
    {
        string? raw =
            doc.Root?
                .Element(ns + "System")?
                .Element(ns + "TimeCreated")?
                .Attribute("SystemTime")?
                .Value;

        return DateTimeOffset.TryParse(
            raw,
            out DateTimeOffset dto)
                ? dto.UtcDateTime
                : null;
    }

    private static string Run(
        string fileName,
        string arguments,
        int timeoutMs)
    {
        try
        {
            var psi =
                new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

            using Process? process =
                Process.Start(psi);

            if (process == null)
                return "";

            string stdout =
                process.StandardOutput.ReadToEnd();

            _ = process.StandardError.ReadToEnd();

            if (!process.WaitForExit(timeoutMs))
            {
                try
                {
                    process.Kill(true);
                }
                catch
                {
                }

                return "";
            }

            return process.ExitCode == 0
                ? stdout
                : "";
        }
        catch
        {
            return "";
        }
    }
}

internal sealed class SystemIntegrityExpansionRecord
{
    public string Kind { get; set; } = "";
    public string Name { get; set; } = "";
    public string SeverityHint { get; set; } = "info";
    public DateTime? TimestampUtc { get; set; }
    public string Detail { get; set; } = "";
}
