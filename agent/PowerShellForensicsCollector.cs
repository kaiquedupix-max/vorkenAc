using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Vorken.Agent;

internal static class PowerShellForensicsCollector
{
    private static readonly string[] SuspiciousTokens =
    {
        "invoke-expression",
        "iex ",
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "iwr ",
        "start-bitstransfer",
        "frombase64string",
        "-encodedcommand",
        "reflection.assembly",
        "assembly]::load",
        "virtualalloc",
        "writeprocessmemory",
        "createremotethread",
        "add-mppreference",
        "set-mppreference",
        "exclusionpath",
        "exclusionprocess",
        "set-executionpolicy bypass",
        "windowstyle hidden",
        "hidden -command",
        "certutil -decode",
        "bitsadmin",
        "mshta ",
        "rundll32 ",
        "regsvr32 ",
        "curl ",
        "wget ",
        "discord.gg/",
        "cdn.discordapp.com/",
        "t.me/"
    };

    public static List<PowerShellArtifactRecord> Collect()
    {
        var result = new List<PowerShellArtifactRecord>();

        CollectPsReadLine(result);
        CollectEventLog(result);

        return result
            .GroupBy(
                x => $"{x.Source}|{x.TimestampUtc:O}|{x.Command}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .OrderByDescending(x => x.TimestampUtc ?? DateTime.MinValue)
            .Take(1800)
            .ToList();
    }

    private static void CollectPsReadLine(
        List<PowerShellArtifactRecord> result)
    {
        string roaming = Environment.GetFolderPath(
            Environment.SpecialFolder.ApplicationData);

        string[] candidates =
        {
            Path.Combine(
                roaming,
                "Microsoft",
                "Windows",
                "PowerShell",
                "PSReadLine",
                "ConsoleHost_history.txt"),
            Path.Combine(
                roaming,
                "Microsoft",
                "Windows",
                "PowerShell",
                "PSReadLine",
                "Visual Studio Code Host_history.txt")
        };

        foreach (string path in candidates.Distinct(
                     StringComparer.OrdinalIgnoreCase))
        {
            if (!File.Exists(path))
                continue;

            try
            {
                string[] lines = File.ReadAllLines(path);

                foreach (string line in lines.TakeLast(5000))
                {
                    AddIfInteresting(
                        result,
                        "PSReadLine",
                        path,
                        line,
                        null,
                        null);
                }
            }
            catch
            {
            }
        }
    }

    private static void CollectEventLog(
        List<PowerShellArtifactRecord> result)
    {
        string[] logs =
        {
            "Microsoft-Windows-PowerShell/Operational",
            "Windows PowerShell"
        };

        foreach (string log in logs)
        {
            foreach (string xml in QueryEvents(
                         log,
                         "*[System[(EventID=4104 or EventID=4103 or EventID=400 or EventID=600)]]",
                         900))
            {
                try
                {
                    XDocument doc = XDocument.Parse(xml);
                    XNamespace ns =
                        "http://schemas.microsoft.com/win/2004/08/events/event";

                    int eventId = int.TryParse(
                        doc.Root?
                            .Element(ns + "System")?
                            .Element(ns + "EventID")?
                            .Value,
                        out int parsed)
                            ? parsed
                            : 0;

                    DateTime? timestamp = TryEventTime(doc, ns);

                    var data = doc.Descendants(ns + "Data")
                        .Select(x => new
                        {
                            Name = x.Attribute("Name")?.Value ?? "",
                            Value = x.Value ?? ""
                        })
                        .ToList();

                    string script = data
                        .Where(x =>
                            x.Name.Equals(
                                "ScriptBlockText",
                                StringComparison.OrdinalIgnoreCase) ||
                            x.Name.Equals(
                                "Payload",
                                StringComparison.OrdinalIgnoreCase) ||
                            x.Name.Equals(
                                "HostApplication",
                                StringComparison.OrdinalIgnoreCase))
                        .Select(x => x.Value)
                        .FirstOrDefault(x =>
                            !string.IsNullOrWhiteSpace(x)) ?? "";

                    if (string.IsNullOrWhiteSpace(script))
                    {
                        script = string.Join(
                            " ",
                            data.Select(x => x.Value)
                                .Where(x =>
                                    !string.IsNullOrWhiteSpace(x)));
                    }

                    AddIfInteresting(
                        result,
                        log,
                        log,
                        script,
                        timestamp,
                        eventId);
                }
                catch
                {
                }
            }
        }
    }

    private static void AddIfInteresting(
        List<PowerShellArtifactRecord> result,
        string source,
        string sourcePath,
        string command,
        DateTime? timestamp,
        int? eventId)
    {
        string normalized = command
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Trim();

        if (normalized.Length == 0)
            return;

        List<string> matches = SuspiciousTokens
            .Where(token =>
                normalized.Contains(
                    token,
                    StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        bool longEncodedBlob =
            Regex.IsMatch(
                normalized,
                @"[A-Za-z0-9+/]{180,}={0,2}",
                RegexOptions.CultureInvariant);

        if (matches.Count == 0 && !longEncodedBlob)
            return;

        string clipped = normalized.Length > 4000
            ? normalized[..4000]
            : normalized;

        result.Add(new PowerShellArtifactRecord
        {
            Source = source,
            SourcePath = sourcePath,
            EventId = eventId,
            TimestampUtc = timestamp,
            Command = clipped,
            MatchedIndicators = matches,
            LongEncodedPayload = longEncodedBlob
        });
    }

    private static IEnumerable<string> QueryEvents(
        string logName,
        string query,
        int count)
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
            if (process == null)
                return result;

            string output = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();

            if (!process.WaitForExit(15000))
            {
                try { process.Kill(true); } catch { }
                return result;
            }

            if (process.ExitCode != 0 ||
                string.IsNullOrWhiteSpace(output))
            {
                return result;
            }

            foreach (Match match in Regex.Matches(
                         output,
                         @"<Event\b.*?</Event>",
                         RegexOptions.Singleline |
                         RegexOptions.IgnoreCase))
            {
                result.Add(match.Value);
            }
        }
        catch
        {
        }

        return result;
    }

    private static DateTime? TryEventTime(
        XDocument doc,
        XNamespace ns)
    {
        try
        {
            string? raw = doc.Root?
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
        catch
        {
            return null;
        }
    }
}

internal sealed class PowerShellArtifactRecord
{
    public string Source { get; set; } = "";
    public string SourcePath { get; set; } = "";
    public int? EventId { get; set; }
    public DateTime? TimestampUtc { get; set; }
    public string Command { get; set; } = "";
    public List<string> MatchedIndicators { get; set; } = new();
    public bool LongEncodedPayload { get; set; }
}
