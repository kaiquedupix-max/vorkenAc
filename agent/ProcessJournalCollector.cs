using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Xml.Linq;

namespace Vorken.Agent;

internal static class ProcessJournalCollector
{
    private const int MaximumEventsPerSource = 5000;

    public static ProcessJournalReport Collect()
    {
        DateTime captured = DateTime.UtcNow;
        var result = new ProcessJournalReport
        {
            CapturedAtUtc = captured,
            BootTimeUtc = captured.AddMilliseconds(-Environment.TickCount64)
        };
        foreach (var source in new[] { ("Security", 4688), ("Security", 4689), ("Microsoft-Windows-Sysmon/Operational", 1), ("Microsoft-Windows-Sysmon/Operational", 5) })
        {
            var status = new JournalSourceStatus { Channel = source.Item1, EventId = source.Item2 };
            result.Sources.Add(status);
            try
            {
                string from = result.BootTimeUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
                string to = captured.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
                string query = $"*[System[(EventID={source.Item2}) and TimeCreated[@SystemTime >= '{from}' and @SystemTime <= '{to}']]]";
                using var reader = new EventLogReader(new EventLogQuery(source.Item1, PathType.LogName, query) { ReverseDirection = true });
                var clock = Stopwatch.StartNew();
                while (status.EventsRead < MaximumEventsPerSource && clock.Elapsed < TimeSpan.FromSeconds(15))
                {
                    using EventRecord? record = reader.ReadEvent(TimeSpan.FromSeconds(1));
                    if (record == null) break;
                    status.EventsRead++;
                    var item = ParseEvent(record.ToXml(), result.BootTimeUtc, captured);
                    if (item != null) result.Events.Add(item);
                }
                status.LimitReached = status.EventsRead == MaximumEventsPerSource || clock.Elapsed >= TimeSpan.FromSeconds(15);
                status.State = status.EventsRead == 0 ? "no-events" : "available";
            }
            catch (Exception ex) when (ex is EventLogException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException)
            {
                status.State = "unavailable";
                status.Error = ex.GetType().Name;
            }
        }
        // Presence/signature are read only for permitted files, never Rust/EAC paths.
        var signatures = new Dictionary<string, (bool Signed, string Signer)>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in result.Events)
        {
            if (!signatures.TryGetValue(item.ProcessPath, out var signature))
            {
                signature = (false, "");
                if (signatures.Count < 1000 && InspectionScope.CanInspectPath(item.ProcessPath))
                    signature = AuthenticodeVerifier.Verify(item.ProcessPath);
                signatures[item.ProcessPath] = signature;
            }
            item.ProcessPresent = ScanFile.Exists(item.ProcessPath);
            try { item.DriveType = new DriveInfo(Path.GetPathRoot(item.ProcessPath)!).DriveType.ToString(); } catch { item.DriveType = "Unknown"; }
            item.Signed = signature.Signed;
            item.SignerSubject = signature.Signer;
        }
        result.Events = result.Events.OrderByDescending(x => x.TimeCreatedUtc).ToList();
        return result;
    }

    internal static ProcessCreationRecord? ParseEvent(string xml, DateTime boot, DateTime captured)
    {
        try
        {
            var document = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var system = document.Root?.Element(ns + "System");
            int.TryParse(system?.Element(ns + "EventID")?.Value, out int eventId);
            string channel = system?.Element(ns + "Channel")?.Value ?? "";
            if (!((eventId is 4688 or 4689 && channel == "Security") || (eventId is 1 or 5 && channel == "Microsoft-Windows-Sysmon/Operational"))) return null;
            if (!DateTimeOffset.TryParse(system?.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var timestamp)) return null;
            if (timestamp.UtcDateTime < boot || timestamp.UtcDateTime > captured) return null;
            var data = document.Descendants(ns + "Data").GroupBy(x => x.Attribute("Name")?.Value ?? "")
                .ToDictionary(x => x.Key, x => x.First().Value, StringComparer.OrdinalIgnoreCase);
            string Value(string key) => data.GetValueOrDefault(key, "");
            string path = Value(eventId == 4688 ? "NewProcessName" : eventId == 4689 ? "ProcessName" : "Image");
            string name = Path.GetFileName(path);
            if (string.IsNullOrWhiteSpace(path) || InspectionScope.IsExcludedProcess(name) || !InspectionScope.CanInspectPath(path)) return null;
            string parent = Value(eventId == 4688 ? "ParentProcessName" : "ParentImage");
            // Do not transmit excluded game paths even when they are a parent process.
            if (InspectionScope.IsExcludedProcess(Path.GetFileName(parent)) || (!string.IsNullOrEmpty(parent) && !InspectionScope.CanInspectPath(parent))) parent = "";
            return new ProcessCreationRecord
            {
                TimeCreatedUtc = timestamp.UtcDateTime, ProcessPath = path, ProcessName = name,
                ParentProcessPath = parent, ParentProcessName = Path.GetFileName(parent),
                ProcessId = Value(eventId == 4688 ? "NewProcessId" : "ProcessId"),
                Source = channel, EventId = eventId
            };
        }
        catch (Exception ex) when (ex is System.Xml.XmlException || ex is ArgumentException) { return null; }
    }
}

internal sealed class ProcessJournalReport
{
    public DateTime BootTimeUtc { get; set; }
    public DateTime CapturedAtUtc { get; set; }
    public List<ProcessCreationRecord> Events { get; set; } = new();
    public List<JournalSourceStatus> Sources { get; set; } = new();
}

internal sealed class JournalSourceStatus
{
    public string Channel { get; set; } = "";
    public int EventId { get; set; }
    public string State { get; set; } = "unavailable";
    public string Error { get; set; } = "";
    public int EventsRead { get; set; }
    public bool LimitReached { get; set; }
}
