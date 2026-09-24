namespace Vorken.Agent;

internal static class ZoneIdentifierCollector
{
    public static List<ZoneIdentifierRecord> Collect()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string value)
        {
            if (!string.IsNullOrWhiteSpace(value) && Directory.Exists(value))
                roots.Add(value);
        }

        string user = Environment.GetFolderPath(
            Environment.SpecialFolder.UserProfile);

        Add(Path.Combine(user, "Downloads"));
        Add(Environment.GetFolderPath(
            Environment.SpecialFolder.DesktopDirectory));
        Add(Path.GetTempPath());

        var result = new List<ZoneIdentifierRecord>();

        foreach (string root in roots)
        {
            foreach (string file in EnumerateFilesLimited(root, 3, 3500))
            {
                if (result.Count >= 5000)
                    break;

                try
                {
                    string streamPath = file + ":Zone.Identifier";

                    if (!File.Exists(streamPath))
                    {
                        // File.Exists() can return false for ADS even when
                        // opening the stream works, so still try below.
                    }

                    string text;

                    using (
                        var stream = new FileStream(
                            streamPath,
                            FileMode.Open,
                            FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete))
                    using (var reader = new StreamReader(stream))
                    {
                        char[] buffer = new char[8192];
                        int read = reader.Read(buffer, 0, buffer.Length);
                        text = new string(buffer, 0, Math.Max(0, read));
                    }

                    if (string.IsNullOrWhiteSpace(text))
                        continue;

                    var values = ParseIni(text);

                    _ = int.TryParse(
                        Get(values, "ZoneId"),
                        out int zoneId);

                    result.Add(new ZoneIdentifierRecord
                    {
                        FileName = Path.GetFileName(file),
                        Path = file,
                        ZoneId = zoneId,
                        HostUrl = Get(values, "HostUrl"),
                        ReferrerUrl = Get(values, "ReferrerUrl"),
                        LastWriteUtc = File.GetLastWriteTimeUtc(file),
                        FileExists = File.Exists(file),
                        Sha256 = TrySha256(file)
                    });
                }
                catch
                {
                }
            }
        }

        return result
            .OrderByDescending(x => x.LastWriteUtc)
            .Take(5000)
            .ToList();
    }

    private static Dictionary<string, string> ParseIni(string text)
    {
        var values = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase);

        foreach (string raw in text.Split(
                     new[] { "\r\n", "\n" },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            string line = raw.Trim();

            if (line.Length == 0 ||
                line.StartsWith("[") ||
                line.StartsWith(";"))
            {
                continue;
            }

            int index = line.IndexOf('=');
            if (index <= 0)
                continue;

            string key = line[..index].Trim();
            string value = line[(index + 1)..].Trim();

            values[key] = value;
        }

        return values;
    }

    private static string Get(
        Dictionary<string, string> values,
        string key) =>
        values.TryGetValue(key, out string? value)
            ? value
            : "";

    private static string TrySha256(string path)
    {
        try
        {
            FileInfo info = new(path);
            if (info.Length > 250L * 1024L * 1024L)
                return "";

            using FileStream stream = new(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);

            return Convert
                .ToHexString(
                    System.Security.Cryptography.SHA256.HashData(stream))
                .ToLowerInvariant();
        }
        catch
        {
            return "";
        }
    }

    private static IEnumerable<string> EnumerateFilesLimited(
        string root,
        int maxDepth,
        int maxFiles)
    {
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((root, 0));

        int yielded = 0;

        while (queue.Count > 0 && yielded < maxFiles)
        {
            (string current, int depth) = queue.Dequeue();

            IEnumerable<string> files;

            try
            {
                files = Directory.EnumerateFiles(current);
            }
            catch
            {
                continue;
            }

            foreach (string file in files)
            {
                yield return file;
                yielded++;

                if (yielded >= maxFiles)
                    yield break;
            }

            if (depth >= maxDepth)
                continue;

            IEnumerable<string> dirs;

            try
            {
                dirs = Directory.EnumerateDirectories(current);
            }
            catch
            {
                continue;
            }

            foreach (string dir in dirs.Take(150))
                queue.Enqueue((dir, depth + 1));
        }
    }
}

internal sealed class ZoneIdentifierRecord
{
    public string FileName { get; set; } = "";
    public string Path { get; set; } = "";
    public int ZoneId { get; set; }
    public string HostUrl { get; set; } = "";
    public string ReferrerUrl { get; set; } = "";
    public DateTime? LastWriteUtc { get; set; }
    public bool FileExists { get; set; }
    public string Sha256 { get; set; } = "";
}
