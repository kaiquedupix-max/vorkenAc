namespace Vorken.Agent;

internal static class AmcacheExecutionCollector
{
    public static List<AmcacheExecutionRecord> Collect()
    {
        var result = new List<AmcacheExecutionRecord>();

        string hive = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "AppCompat",
            "Programs",
            "Amcache.hve");

        if (!File.Exists(hive))
            return result;

        try
        {
            bool isNew = global::Amcache.Helper.IsNewFormat(hive, false);

            if (!isNew)
                return result;

            var parsed = new global::Amcache.AmcacheNew(
                hive,
                recoverDeleted: true,
                noLogs: false);

            foreach (var entry in parsed.UnassociatedFileEntries)
            {
                AddEntry(
                    result,
                    entry,
                    "Unassociated",
                    null);

                if (result.Count >= 6000)
                    break;
            }

            if (result.Count < 6000)
            {
                foreach (var program in parsed.ProgramsEntries)
                {
                    foreach (var entry in program.FileEntries)
                    {
                        AddEntry(
                            result,
                            entry,
                            program.Name,
                            program.Publisher);

                        if (result.Count >= 6000)
                            break;
                    }

                    if (result.Count >= 6000)
                        break;
                }
            }
        }
        catch
        {
        }

        return result
            .OrderByDescending(x => x.FileKeyLastWriteUtc)
            .Take(6000)
            .ToList();
    }

    private static void AddEntry(
        List<AmcacheExecutionRecord> target,
        global::Amcache.Classes.FileEntryNew entry,
        string applicationName,
        string? programPublisher)
    {
        try
        {
            string fullPath = entry.FullPath ?? "";
            string name = !string.IsNullOrWhiteSpace(entry.Name)
                ? entry.Name
                : Path.GetFileName(fullPath);

            if (string.IsNullOrWhiteSpace(name) &&
                string.IsNullOrWhiteSpace(fullPath))
            {
                return;
            }

            target.Add(new AmcacheExecutionRecord
            {
                Name = name ?? "",
                FullPath = fullPath,
                Sha1 = entry.SHA1 ?? "",
                ApplicationName = applicationName ?? entry.ApplicationName ?? "",
                ProductName = entry.ProductName ?? "",
                Publisher = !string.IsNullOrWhiteSpace(programPublisher)
                    ? programPublisher
                    : entry.Publisher ?? "",
                Description = entry.Description ?? "",
                OriginalFileName = entry.OriginalFileName ?? "",
                IsPeFile = entry.IsPeFile,
                IsOsComponent = entry.IsOsComponent,
                FileSize = entry.Size,
                Usn = entry.Usn,
                FileKeyLastWriteUtc = entry.FileKeyLastWriteTimestamp.UtcDateTime,
                LinkDateUtc = entry.LinkDate?.UtcDateTime,
                FilePresent = SafeExists(fullPath),
                DriveType = GetDriveType(fullPath)
            });
        }
        catch
        {
        }
    }

    private static bool SafeExists(string path)
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

    private static string GetDriveType(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path))
                return "";

            if (path.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase))
                return "Network";

            string? root = Path.GetPathRoot(path);
            if (string.IsNullOrWhiteSpace(root))
                return "";

            return new DriveInfo(root).DriveType.ToString();
        }
        catch
        {
            return "";
        }
    }
}

internal sealed class AmcacheExecutionRecord
{
    public string Name { get; set; } = "";
    public string FullPath { get; set; } = "";
    public string Sha1 { get; set; } = "";
    public string ApplicationName { get; set; } = "";
    public string ProductName { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string Description { get; set; } = "";
    public string OriginalFileName { get; set; } = "";
    public bool IsPeFile { get; set; }
    public bool IsOsComponent { get; set; }
    public long FileSize { get; set; }
    public ulong Usn { get; set; }
    public DateTime FileKeyLastWriteUtc { get; set; }
    public DateTime? LinkDateUtc { get; set; }
    public bool FilePresent { get; set; }
    public string DriveType { get; set; } = "";
}
