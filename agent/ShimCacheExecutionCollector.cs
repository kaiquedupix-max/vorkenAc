namespace Vorken.Agent;

internal static class ShimCacheExecutionCollector
{
    public static List<ShimCacheRecord> Collect()
    {
        var result = new List<ShimCacheRecord>();

        try
        {
            var parser = new global::AppCompatCache.AppCompatCache(
                filename: "",
                controlSet: -1,
                noLogs: true);

            foreach (var cache in parser.Caches)
            {
                foreach (var entry in cache.Entries)
                {
                    if (string.IsNullOrWhiteSpace(entry.Path))
                        continue;

                    result.Add(new ShimCacheRecord
                    {
                        Path = entry.Path,
                        Executed = entry.Executed.ToString(),
                        LastModifiedUtc = entry.LastModifiedTimeUTC?.UtcDateTime,
                        ControlSet = entry.ControlSet,
                        InsertFlags = entry.InsertFlags.ToString(),
                        FilePresent = SafeExists(entry.Path),
                        DriveType = GetDriveType(entry.Path)
                    });

                    if (result.Count >= 6000)
                        break;
                }

                if (result.Count >= 6000)
                    break;
            }
        }
        catch
        {
        }

        return result
            .OrderByDescending(x => x.LastModifiedUtc ?? DateTime.MinValue)
            .Take(6000)
            .ToList();
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

internal sealed class ShimCacheRecord
{
    public string Path { get; set; } = "";
    public string Executed { get; set; } = "";
    public DateTime? LastModifiedUtc { get; set; }
    public int ControlSet { get; set; }
    public string InsertFlags { get; set; } = "";
    public bool FilePresent { get; set; }
    public string DriveType { get; set; } = "";
}
