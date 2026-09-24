namespace Vorken.Agent;

internal static class CrashArtifactCollector
{
    public static List<CrashArtifactRecord> Collect()
    {
        var result = new List<CrashArtifactRecord>();

        string local = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);

        string programData = Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData);

        string windows = Environment.GetFolderPath(
            Environment.SpecialFolder.Windows);

        string[] roots =
        {
            Path.Combine(
                programData,
                "Microsoft",
                "Windows",
                "WER",
                "ReportArchive"),
            Path.Combine(
                programData,
                "Microsoft",
                "Windows",
                "WER",
                "ReportQueue"),
            Path.Combine(
                local,
                "Microsoft",
                "Windows",
                "WER",
                "ReportArchive"),
            Path.Combine(
                local,
                "Microsoft",
                "Windows",
                "WER",
                "ReportQueue"),
            Path.Combine(
                windows,
                "Minidump"),
            Path.Combine(
                local,
                "CrashDumps")
        };

        foreach (string root in roots.Distinct(
                     StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(root))
                continue;

            CollectRoot(root, result);

            if (result.Count >= 2500)
                break;
        }

        return result
            .OrderByDescending(
                x => x.TimestampUtc ?? DateTime.MinValue)
            .Take(2500)
            .ToList();
    }

    private static void CollectRoot(
        string root,
        List<CrashArtifactRecord> result)
    {
        IEnumerable<string> files;

        try
        {
            files = Directory.EnumerateFiles(
                root,
                "*",
                SearchOption.AllDirectories);
        }
        catch
        {
            return;
        }

        foreach (string file in files.Take(6000))
        {
            if (result.Count >= 2500)
                break;

            try
            {
                string name = Path.GetFileName(file);

                if (name.Equals(
                        "Report.wer",
                        StringComparison.OrdinalIgnoreCase))
                {
                    ParseWer(file, result);
                    continue;
                }

                string ext = Path.GetExtension(file);

                if (
                    ext.Equals(
                        ".dmp",
                        StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(
                        ".mdmp",
                        StringComparison.OrdinalIgnoreCase))
                {
                    FileInfo info = new(file);

                    result.Add(new CrashArtifactRecord
                    {
                        Source = "Crash dump",
                        ArtifactPath = file,
                        AppName = Path.GetFileNameWithoutExtension(file),
                        TimestampUtc = info.LastWriteTimeUtc,
                        Size = info.Length
                    });
                }
            }
            catch
            {
            }
        }
    }

    private static void ParseWer(
        string path,
        List<CrashArtifactRecord> result)
    {
        try
        {
            string[] lines = File.ReadAllLines(path);

            string appName = "";
            string appPath = "";
            string modulePath = "";
            string eventType = "";

            foreach (string raw in lines.Take(4000))
            {
                string line = raw.Trim();
                int index = line.IndexOf('=');

                if (index <= 0)
                    continue;

                string key = line[..index].Trim();
                string value = line[(index + 1)..].Trim();

                if (
                    key.Equals(
                        "AppName",
                        StringComparison.OrdinalIgnoreCase))
                {
                    appName = value;
                }
                else if (
                    key.Equals(
                        "AppPath",
                        StringComparison.OrdinalIgnoreCase))
                {
                    appPath = value;
                }
                else if (
                    key.Contains(
                        "FaultModule",
                        StringComparison.OrdinalIgnoreCase) ||
                    key.Contains(
                        "FaultingModule",
                        StringComparison.OrdinalIgnoreCase))
                {
                    if (
                        string.IsNullOrWhiteSpace(modulePath) &&
                        (
                            value.Contains(".dll",
                                StringComparison.OrdinalIgnoreCase) ||
                            value.Contains(".exe",
                                StringComparison.OrdinalIgnoreCase)
                        )
                    ) {
                        modulePath = value;
                    }
                }
                else if (
                    key.Equals(
                        "EventType",
                        StringComparison.OrdinalIgnoreCase))
                {
                    eventType = value;
                }
            }

            FileInfo info = new(path);

            result.Add(new CrashArtifactRecord
            {
                Source = "Windows Error Reporting",
                ArtifactPath = path,
                AppName = appName,
                AppPath = appPath,
                FaultingModulePath = modulePath,
                EventType = eventType,
                TimestampUtc = info.LastWriteTimeUtc,
                Size = info.Length
            });
        }
        catch
        {
        }
    }
}

internal sealed class CrashArtifactRecord
{
    public string Source { get; set; } = "";
    public string ArtifactPath { get; set; } = "";
    public string AppName { get; set; } = "";
    public string AppPath { get; set; } = "";
    public string FaultingModulePath { get; set; } = "";
    public string EventType { get; set; } = "";
    public DateTime? TimestampUtc { get; set; }
    public long Size { get; set; }
}
