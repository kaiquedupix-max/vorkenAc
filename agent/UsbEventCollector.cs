using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Vorken.Agent;

internal static class UsbEventCollector
{
    public static List<UsbDeviceEventRecord> Collect()
    {
        var result = new List<UsbDeviceEventRecord>();

        QueryLog(
            "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
            "*[System[(EventID=2003 or EventID=2100 or EventID=2102)]]",
            600,
            result);

        QueryLog(
            "Microsoft-Windows-Partition/Diagnostic",
            "*[System[(EventID=1006)]]",
            600,
            result);

        QueryLog(
            "Microsoft-Windows-Kernel-PnP/Configuration",
            "*[System[(EventID=400 or EventID=410 or EventID=430)]]",
            600,
            result);

        return result
            .OrderByDescending(x => x.TimeCreatedUtc)
            .GroupBy(x => $"{x.Provider}|{x.EventId}|{x.TimeCreatedUtc:O}|{x.DeviceId}|{x.Evidence}")
            .Select(x => x.First())
            .Take(1500)
            .ToList();
    }

    public static void EnrichUsbHistory(
        List<UsbHistoryRecord> history,
        List<UsbDeviceEventRecord> events)
    {
        foreach (UsbHistoryRecord item in history)
        {
            string serial = Normalize(item.InstanceId);
            string name = Normalize(item.FriendlyName);

            var matching = events
                .Where(e =>
                {
                    string haystack = Normalize(
                        (e.DeviceId ?? "") + " " + (e.Evidence ?? ""));

                    bool serialMatch =
                        serial.Length >= 4 && haystack.Contains(serial);

                    bool nameMatch =
                        name.Length >= 6 && haystack.Contains(name);

                    return serialMatch || nameMatch;
                })
                .ToList();

            item.LastConnectedUtc = matching
                .Where(x => x.EventType == "connect")
                .OrderByDescending(x => x.TimeCreatedUtc)
                .Select(x => (DateTime?)x.TimeCreatedUtc)
                .FirstOrDefault();

            item.LastDisconnectedUtc = matching
                .Where(x => x.EventType == "disconnect")
                .OrderByDescending(x => x.TimeCreatedUtc)
                .Select(x => (DateTime?)x.TimeCreatedUtc)
                .FirstOrDefault();

            item.TimelineSource = item.LastDisconnectedUtc.HasValue
                ? "DriverFrameworks-UserMode Event 2102"
                : item.LastConnectedUtc.HasValue
                    ? "Windows device event log"
                    : "";
        }
    }

    private static void QueryLog(
        string logName,
        string query,
        int maxEvents,
        List<UsbDeviceEventRecord> target)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wevtutil.exe",
                Arguments =
                    $"qe \"{logName}\" /q:\"{query}\" /f:xml /rd:true /c:{maxEvents}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using Process? process = Process.Start(psi);
            if (process == null) return;

            string output = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();

            if (!process.WaitForExit(12000))
            {
                try { process.Kill(true); } catch { }
                return;
            }

            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
                return;

            foreach (Match match in Regex.Matches(
                         output,
                         @"<Event\b.*?</Event>",
                         RegexOptions.Singleline | RegexOptions.IgnoreCase))
            {
                TryParseEvent(match.Value, logName, target);
            }
        }
        catch
        {
        }
    }

    private static void TryParseEvent(
        string xml,
        string fallbackProvider,
        List<UsbDeviceEventRecord> target)
    {
        try
        {
            XDocument doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";

            XElement? system = doc.Root?.Element(ns + "System");
            if (system == null) return;

            int eventId = int.TryParse(
                system.Element(ns + "EventID")?.Value,
                out int parsedId)
                ? parsedId
                : 0;

            string provider =
                system.Element(ns + "Provider")?.Attribute("Name")?.Value ??
                fallbackProvider;

            DateTime timeUtc = DateTime.UtcNow;
            string? timeRaw =
                system.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value;

            if (DateTimeOffset.TryParse(timeRaw, out DateTimeOffset dto))
                timeUtc = dto.UtcDateTime;

            var values = doc
                .Descendants(ns + "Data")
                .Select(x => new
                {
                    Name = x.Attribute("Name")?.Value ?? "",
                    Value = (x.Value ?? "").Trim()
                })
                .Where(x => !string.IsNullOrWhiteSpace(x.Value))
                .ToList();

            if (values.Count == 0)
            {
                values = doc
                    .Descendants()
                    .Where(x => !x.HasElements && !string.IsNullOrWhiteSpace(x.Value))
                    .Select(x => new
                    {
                        Name = x.Name.LocalName,
                        Value = x.Value.Trim()
                    })
                    .Take(80)
                    .ToList();
            }

            string joined = string.Join(
                " | ",
                values.Select(x =>
                    string.IsNullOrWhiteSpace(x.Name)
                        ? x.Value
                        : x.Name + "=" + x.Value));

            string? deviceId = FindDeviceIdentifier(values.Select(x => x.Value));

            if (string.IsNullOrWhiteSpace(deviceId) && eventId == 1006)
            {
                string? parentId = values
                    .FirstOrDefault(x => x.Name.Equals("ParentId", StringComparison.OrdinalIgnoreCase))
                    ?.Value;

                string? serialNumber = values
                    .FirstOrDefault(x => x.Name.Equals("SerialNumber", StringComparison.OrdinalIgnoreCase))
                    ?.Value;

                deviceId = !string.IsNullOrWhiteSpace(parentId)
                    ? parentId
                    : serialNumber;
            }

            string eventType = eventId switch
            {
                2003 => "connect",
                2102 => "disconnect",
                400 or 410 or 430 => "connect",
                1006 => GetPartitionEventType(values),
                _ => "device_activity"
            };

            bool usbRelated =
                !string.IsNullOrWhiteSpace(deviceId) ||
                joined.Contains("USB", StringComparison.OrdinalIgnoreCase) ||
                joined.Contains("VID_", StringComparison.OrdinalIgnoreCase) ||
                joined.Contains("PID_", StringComparison.OrdinalIgnoreCase) ||
                joined.Contains("removable", StringComparison.OrdinalIgnoreCase);

            if (!usbRelated &&
                !provider.Contains("Partition", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            target.Add(new UsbDeviceEventRecord
            {
                Provider = provider,
                EventId = eventId,
                EventType = eventType,
                TimeCreatedUtc = timeUtc,
                DeviceId = deviceId ?? "",
                Evidence = joined.Length > 1800 ? joined[..1800] : joined
            });
        }
        catch
        {
        }
    }

    private static string GetPartitionEventType(
        IEnumerable<dynamic> values)
    {
        try
        {
            foreach (var item in values)
            {
                string name = Convert.ToString(item.Name) ?? "";
                if (!name.Equals("Capacity", StringComparison.OrdinalIgnoreCase))
                    continue;

                string raw = Convert.ToString(item.Value) ?? "";
                if (!ulong.TryParse(raw, out ulong capacity))
                    break;

                // Partition/Diagnostic Event 1006 uses Capacity=0 for removal.
                return capacity == 0 ? "disconnect" : "connect";
            }
        }
        catch
        {
        }

        return "partition_activity";
    }

    private static string? FindDeviceIdentifier(IEnumerable<string> values)
    {
        foreach (string value in values)
        {
            string normalized = value.Trim();

            if (normalized.Contains("USBSTOR\\", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("USB\\VID_", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("SWD\\WPDBUSENUM", StringComparison.OrdinalIgnoreCase) ||
                (normalized.Contains("VID_", StringComparison.OrdinalIgnoreCase) &&
                 normalized.Contains("PID_", StringComparison.OrdinalIgnoreCase)))
            {
                return normalized.Length > 500 ? normalized[..500] : normalized;
            }
        }

        return null;
    }

    private static string Normalize(string? value) =>
        Regex.Replace(
            (value ?? "").ToUpperInvariant(),
            @"[^A-Z0-9]+",
            "");
}

internal sealed class UsbDeviceEventRecord
{
    public string Provider { get; set; } = "";
    public int EventId { get; set; }
    public string EventType { get; set; } = "";
    public DateTime TimeCreatedUtc { get; set; }
    public string DeviceId { get; set; } = "";
    public string Evidence { get; set; } = "";
}
