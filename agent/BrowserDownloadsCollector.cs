using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Text.Json;

namespace Vorken.Agent;

internal static class BrowserDownloadsCollector
{
    private static readonly DateTime ChromiumEpoch =
        new(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static readonly DateTime UnixEpoch =
        DateTime.UnixEpoch;

    public static List<BrowserDownloadRecord> Collect()
    {
        var result = new List<BrowserDownloadRecord>();

        foreach (BrowserProfile profile in EnumerateChromiumProfiles())
        {
            try
            {
                result.AddRange(ReadChromiumProfile(profile));
            }
            catch
            {
            }
        }

        foreach (BrowserProfile profile in EnumerateFirefoxProfiles())
        {
            try
            {
                result.AddRange(ReadFirefoxProfile(profile));
            }
            catch
            {
            }
        }

        return result
            .GroupBy(
                x => string.Join(
                    "|",
                    x.Browser,
                    x.Profile,
                    x.TargetPath,
                    x.SourceUrl,
                    x.StartTimeUtc?.Ticks ?? 0),
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .OrderByDescending(x => x.StartTimeUtc ?? DateTime.MinValue)
            .Take(5000)
            .ToList();
    }

    private static IEnumerable<BrowserProfile> EnumerateChromiumProfiles()
    {
        string local = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);

        string roaming = Environment.GetFolderPath(
            Environment.SpecialFolder.ApplicationData);

        var roots = new[]
        {
            new { Browser = "Google Chrome", Path = Path.Combine(local, "Google", "Chrome", "User Data"), RootIsProfile = false },
            new { Browser = "Microsoft Edge", Path = Path.Combine(local, "Microsoft", "Edge", "User Data"), RootIsProfile = false },
            new { Browser = "Brave", Path = Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"), RootIsProfile = false },
            new { Browser = "Chromium", Path = Path.Combine(local, "Chromium", "User Data"), RootIsProfile = false },
            new { Browser = "Vivaldi", Path = Path.Combine(local, "Vivaldi", "User Data"), RootIsProfile = false },
            new { Browser = "Yandex", Path = Path.Combine(local, "Yandex", "YandexBrowser", "User Data"), RootIsProfile = false },
            new { Browser = "Opera", Path = Path.Combine(roaming, "Opera Software", "Opera Stable"), RootIsProfile = true },
            new { Browser = "Opera GX", Path = Path.Combine(roaming, "Opera Software", "Opera GX Stable"), RootIsProfile = true },
        };

        foreach (var root in roots)
        {
            if (!Directory.Exists(root.Path))
                continue;

            if (root.RootIsProfile)
            {
                string history = Path.Combine(root.Path, "History");
                if (File.Exists(history))
                {
                    yield return new BrowserProfile
                    {
                        Browser = root.Browser,
                        Profile = Path.GetFileName(root.Path),
                        DatabasePath = history,
                        Kind = BrowserDatabaseKind.Chromium
                    };
                }

                continue;
            }

            IEnumerable<string> dirs;
            try
            {
                dirs = Directory.EnumerateDirectories(root.Path);
            }
            catch
            {
                continue;
            }

            foreach (string dir in dirs)
            {
                string name = Path.GetFileName(dir);

                if (!name.Equals("Default", StringComparison.OrdinalIgnoreCase) &&
                    !name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase) &&
                    !name.Equals("Guest Profile", StringComparison.OrdinalIgnoreCase) &&
                    !name.StartsWith("System Profile", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string history = Path.Combine(dir, "History");
                if (!File.Exists(history))
                    continue;

                yield return new BrowserProfile
                {
                    Browser = root.Browser,
                    Profile = name,
                    DatabasePath = history,
                    Kind = BrowserDatabaseKind.Chromium
                };
            }
        }
    }

    private static IEnumerable<BrowserProfile> EnumerateFirefoxProfiles()
    {
        string roaming = Environment.GetFolderPath(
            Environment.SpecialFolder.ApplicationData);

        string root = Path.Combine(
            roaming,
            "Mozilla",
            "Firefox",
            "Profiles");

        if (!Directory.Exists(root))
            yield break;

        IEnumerable<string> dirs;
        try
        {
            dirs = Directory.EnumerateDirectories(root);
        }
        catch
        {
            yield break;
        }

        foreach (string dir in dirs)
        {
            string db = Path.Combine(dir, "places.sqlite");
            if (!File.Exists(db))
                continue;

            yield return new BrowserProfile
            {
                Browser = "Mozilla Firefox",
                Profile = Path.GetFileName(dir),
                DatabasePath = db,
                Kind = BrowserDatabaseKind.Firefox
            };
        }
    }

    private static List<BrowserDownloadRecord> ReadChromiumProfile(
        BrowserProfile profile)
    {
        var result = new List<BrowserDownloadRecord>();
        string? snapshot = CreateSqliteSnapshot(profile.DatabasePath);

        if (snapshot is null)
            return result;

        try
        {
            using var connection = Open(snapshot);

            if (!TableExists(connection, "downloads"))
                return result;

            HashSet<string> columns = GetColumns(connection, "downloads");

            string select = string.Join(
                ",",
                new[]
                {
                    Expr(columns, "id", "0"),
                    Expr(columns, "current_path", "''"),
                    Expr(columns, "target_path", "''"),
                    Expr(columns, "start_time", "0"),
                    Expr(columns, "end_time", "0"),
                    Expr(columns, "state", "-1"),
                    Expr(columns, "danger_type", "-1"),
                    Expr(columns, "received_bytes", "0"),
                    Expr(columns, "total_bytes", "0"),
                    Expr(columns, "opened", "0"),
                    Expr(columns, "referrer", "''"),
                    Expr(columns, "site_url", "''"),
                    Expr(columns, "tab_url", "''"),
                    Expr(columns, "tab_referrer_url", "''"),
                    Expr(columns, "http_method", "''"),
                    Expr(columns, "by_ext_name", "''"),
                    Expr(columns, "mime_type", "''"),
                    Expr(columns, "original_mime_type", "''")
                });

            var byId = new Dictionary<long, BrowserDownloadRecord>();

            using (var command = connection.CreateCommand())
            {
                command.CommandText =
                    $"SELECT {select} FROM downloads ORDER BY start_time DESC LIMIT 5000";

                using SqliteDataReader reader = command.ExecuteReader();

                while (reader.Read())
                {
                    long id = GetInt64(reader, 0);
                    string currentPath = GetString(reader, 1);
                    string targetPath = GetString(reader, 2);

                    string effectivePath =
                        !string.IsNullOrWhiteSpace(targetPath)
                            ? targetPath
                            : currentPath;

                    var record = new BrowserDownloadRecord
                    {
                        Browser = profile.Browser,
                        Profile = profile.Profile,
                        TargetPath = effectivePath,
                        CurrentPath = currentPath,
                        FileName = SafeFileName(effectivePath),
                        FileExists = SafeExists(effectivePath),
                        StartTimeUtc = ChromiumTime(GetInt64(reader, 3)),
                        EndTimeUtc = ChromiumTime(GetInt64(reader, 4)),
                        State = ChromiumState(GetInt32(reader, 5)),
                        DangerType = GetInt32(reader, 6),
                        ReceivedBytes = GetInt64(reader, 7),
                        TotalBytes = GetInt64(reader, 8),
                        Opened = GetInt32(reader, 9) != 0,
                        ReferrerUrl = GetString(reader, 10),
                        SiteUrl = GetString(reader, 11),
                        PageUrl = FirstNonEmpty(
                            GetString(reader, 12),
                            GetString(reader, 13),
                            GetString(reader, 10),
                            GetString(reader, 11)),
                        HttpMethod = GetString(reader, 14),
                        InitiatedByExtension = GetString(reader, 15),
                        MimeType = FirstNonEmpty(
                            GetString(reader, 16),
                            GetString(reader, 17)),
                        DatabaseSource = "Chromium History/downloads"
                    };

                    record.FileMissing =
                        !string.IsNullOrWhiteSpace(record.TargetPath) &&
                        !record.FileExists;

                    byId[id] = record;
                    result.Add(record);
                }
            }

            if (TableExists(connection, "downloads_url_chains"))
            {
                using var command = connection.CreateCommand();
                command.CommandText =
                    @"SELECT id, chain_index, url
                      FROM downloads_url_chains
                      ORDER BY id ASC, chain_index ASC";

                using SqliteDataReader reader = command.ExecuteReader();

                while (reader.Read())
                {
                    long id = GetInt64(reader, 0);
                    if (!byId.TryGetValue(id, out BrowserDownloadRecord? record))
                        continue;

                    string url = GetString(reader, 2);
                    if (string.IsNullOrWhiteSpace(url))
                        continue;

                    record.UrlChain.Add(url);
                }

                foreach (BrowserDownloadRecord record in result)
                {
                    record.SourceUrl =
                        record.UrlChain.FirstOrDefault() ?? "";

                    record.FinalUrl =
                        record.UrlChain.LastOrDefault() ??
                        record.SourceUrl;
                }
            }

            foreach (BrowserDownloadRecord record in result)
            {
                if (string.IsNullOrWhiteSpace(record.SourceUrl))
                    record.SourceUrl = FirstNonEmpty(
                        record.ReferrerUrl,
                        record.SiteUrl,
                        record.PageUrl);

                if (string.IsNullOrWhiteSpace(record.FinalUrl))
                    record.FinalUrl = record.SourceUrl;
            }
        }
        finally
        {
            CleanupSnapshot(snapshot);
        }

        return result;
    }

    private static List<BrowserDownloadRecord> ReadFirefoxProfile(
        BrowserProfile profile)
    {
        var result = new List<BrowserDownloadRecord>();
        string? snapshot = CreateSqliteSnapshot(profile.DatabasePath);

        if (snapshot is null)
            return result;

        try
        {
            using var connection = Open(snapshot);

            if (!TableExists(connection, "moz_places") ||
                !TableExists(connection, "moz_annos") ||
                !TableExists(connection, "moz_anno_attributes"))
            {
                return result;
            }

            string query =
                @"SELECT
                    p.id,
                    p.url,
                    a.content,
                    a.dateAdded,
                    a.lastModified
                  FROM moz_annos a
                  JOIN moz_anno_attributes aa
                    ON aa.id = a.anno_attribute_id
                  JOIN moz_places p
                    ON p.id = a.place_id
                  WHERE aa.name = 'downloads/destinationFileURI'
                  ORDER BY a.dateAdded DESC
                  LIMIT 5000";

            using var command = connection.CreateCommand();
            command.CommandText = query;

            using SqliteDataReader reader = command.ExecuteReader();

            while (reader.Read())
            {
                long placeId = GetInt64(reader, 0);
                string sourceUrl = GetString(reader, 1);
                string destinationUri = GetString(reader, 2);
                string targetPath = FileUriToPath(destinationUri);

                var record = new BrowserDownloadRecord
                {
                    Browser = profile.Browser,
                    Profile = profile.Profile,
                    SourceUrl = sourceUrl,
                    FinalUrl = sourceUrl,
                    TargetPath = targetPath,
                    CurrentPath = targetPath,
                    FileName = SafeFileName(targetPath),
                    FileExists = SafeExists(targetPath),
                    StartTimeUtc = FirefoxTime(GetInt64(reader, 3)),
                    EndTimeUtc = FirefoxTime(GetInt64(reader, 4)),
                    State = "history",
                    ReferrerUrl = "",
                    SiteUrl = "",
                    PageUrl = sourceUrl,
                    MimeType = "",
                    DatabaseSource = "Firefox places.sqlite/moz_annos",
                    FirefoxPlaceId = placeId
                };

                record.FileMissing =
                    !string.IsNullOrWhiteSpace(record.TargetPath) &&
                    !record.FileExists;

                result.Add(record);
            }

            TryAddFirefoxMetadata(connection, result);
        }
        finally
        {
            CleanupSnapshot(snapshot);
        }

        return result;
    }

    private static void TryAddFirefoxMetadata(
        SqliteConnection connection,
        List<BrowserDownloadRecord> records)
    {
        if (records.Count == 0)
            return;

        var byPlaceId = records
            .Where(x => x.FirefoxPlaceId.HasValue)
            .GroupBy(x => x.FirefoxPlaceId!.Value)
            .ToDictionary(x => x.Key, x => x.First());

        try
        {
            using var command = connection.CreateCommand();
            command.CommandText =
                @"SELECT
                    a.place_id,
                    a.content
                  FROM moz_annos a
                  JOIN moz_anno_attributes aa
                    ON aa.id = a.anno_attribute_id
                  WHERE aa.name = 'downloads/metaData'";

            using SqliteDataReader reader = command.ExecuteReader();

            while (reader.Read())
            {
                long placeId = GetInt64(reader, 0);
                if (!byPlaceId.TryGetValue(
                        placeId,
                        out BrowserDownloadRecord? record))
                {
                    continue;
                }

                string json = GetString(reader, 1);
                if (string.IsNullOrWhiteSpace(json))
                    continue;

                try
                {
                    using JsonDocument doc = JsonDocument.Parse(json);
                    JsonElement root = doc.RootElement;

                    if (root.TryGetProperty("fileSize", out JsonElement size) &&
                        size.TryGetInt64(out long fileSize))
                    {
                        record.TotalBytes = fileSize;
                    }

                    if (root.TryGetProperty("state", out JsonElement state))
                    {
                        record.State = state.ValueKind switch
                        {
                            JsonValueKind.Number => state.GetInt32().ToString(
                                CultureInfo.InvariantCulture),
                            JsonValueKind.String => state.GetString() ?? record.State,
                            _ => record.State
                        };
                    }

                    if (root.TryGetProperty("endTime", out JsonElement endTime) &&
                        endTime.TryGetInt64(out long firefoxMs))
                    {
                        try
                        {
                            record.EndTimeUtc =
                                DateTimeOffset
                                    .FromUnixTimeMilliseconds(firefoxMs)
                                    .UtcDateTime;
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
            }
        }
        catch
        {
        }
    }

    private static string? CreateSqliteSnapshot(string source)
    {
        string? directory = null;

        try
        {
            directory = Path.Combine(
                Path.GetTempPath(),
                "Vorken",
                "BrowserDb",
                Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(directory);

            string destination = Path.Combine(
                directory,
                Path.GetFileName(source));

            CopyOpenFile(source, destination);

            foreach (string suffix in new[] { "-wal", "-shm" })
            {
                string sidecar = source + suffix;
                if (!File.Exists(sidecar))
                    continue;

                try
                {
                    CopyOpenFile(
                        sidecar,
                        destination + suffix);
                }
                catch
                {
                }
            }

            return destination;
        }
        catch
        {
            if (!string.IsNullOrWhiteSpace(directory))
            {
                try { Directory.Delete(directory, recursive: true); }
                catch { }
            }

            return null;
        }
    }

    private static void CopyOpenFile(
        string source,
        string destination)
    {
        using var input = new FileStream(
            source,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);

        using var output = new FileStream(
            destination,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None);

        input.CopyTo(output);
    }

    private static SqliteConnection Open(string path)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        };

        var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        return connection;
    }

    private static bool TableExists(
        SqliteConnection connection,
        string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$name LIMIT 1";
        command.Parameters.AddWithValue("$name", table);

        return command.ExecuteScalar() is not null;
    }

    private static HashSet<string> GetColumns(
        SqliteConnection connection,
        string table)
    {
        var result = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);

        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info([{table.Replace("]", "]]")}])";

        using SqliteDataReader reader = command.ExecuteReader();

        while (reader.Read())
        {
            string name = reader.GetString(1);
            if (!string.IsNullOrWhiteSpace(name))
                result.Add(name);
        }

        return result;
    }

    private static string Expr(
        HashSet<string> columns,
        string name,
        string fallback) =>
        columns.Contains(name)
            ? $"[{name}]"
            : fallback;

    private static DateTime? ChromiumTime(long microseconds)
    {
        if (microseconds <= 0)
            return null;

        try
        {
            return ChromiumEpoch.AddTicks(
                checked(microseconds * 10L));
        }
        catch
        {
            return null;
        }
    }

    private static DateTime? FirefoxTime(long microseconds)
    {
        if (microseconds <= 0)
            return null;

        try
        {
            return UnixEpoch.AddTicks(
                checked(microseconds * 10L));
        }
        catch
        {
            return null;
        }
    }

    private static string ChromiumState(int value) =>
        value switch
        {
            0 => "in_progress",
            1 => "complete",
            2 => "cancelled",
            3 => "interrupted",
            4 => "interrupted",
            _ => value.ToString(CultureInfo.InvariantCulture)
        };

    private static string FileUriToPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";

        try
        {
            if (Uri.TryCreate(
                    value,
                    UriKind.Absolute,
                    out Uri? uri) &&
                uri.IsFile)
            {
                return uri.LocalPath;
            }
        }
        catch
        {
        }

        return Uri.UnescapeDataString(
            value
                .Replace("file:///", "", StringComparison.OrdinalIgnoreCase)
                .Replace('/', Path.DirectorySeparatorChar));
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path) ?? ""; }
        catch { return ""; }
    }

    private static bool SafeExists(string path)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(path) &&
                   File.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    private static long GetInt64(
        SqliteDataReader reader,
        int ordinal)
    {
        if (reader.IsDBNull(ordinal))
            return 0;

        try { return reader.GetInt64(ordinal); }
        catch
        {
            try
            {
                return Convert.ToInt64(
                    reader.GetValue(ordinal),
                    CultureInfo.InvariantCulture);
            }
            catch
            {
                return 0;
            }
        }
    }

    private static int GetInt32(
        SqliteDataReader reader,
        int ordinal)
    {
        long value = GetInt64(reader, ordinal);
        if (value > int.MaxValue) return int.MaxValue;
        if (value < int.MinValue) return int.MinValue;
        return (int)value;
    }

    private static string GetString(
        SqliteDataReader reader,
        int ordinal)
    {
        if (reader.IsDBNull(ordinal))
            return "";

        try { return reader.GetString(ordinal) ?? ""; }
        catch
        {
            return Convert.ToString(
                reader.GetValue(ordinal),
                CultureInfo.InvariantCulture) ?? "";
        }
    }

    private static void CleanupSnapshot(string path)
    {
        try
        {
            string? directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory) &&
                Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch
        {
        }
    }

    private static string FirstNonEmpty(params string[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";
}

internal enum BrowserDatabaseKind
{
    Chromium,
    Firefox
}

internal sealed class BrowserProfile
{
    public string Browser { get; set; } = "";
    public string Profile { get; set; } = "";
    public string DatabasePath { get; set; } = "";
    public BrowserDatabaseKind Kind { get; set; }
}

internal sealed class BrowserDownloadRecord
{
    public string Browser { get; set; } = "";
    public string Profile { get; set; } = "";
    public string FileName { get; set; } = "";
    public string TargetPath { get; set; } = "";
    public string CurrentPath { get; set; } = "";
    public bool FileExists { get; set; }
    public bool FileMissing { get; set; }
    public DateTime? StartTimeUtc { get; set; }
    public DateTime? EndTimeUtc { get; set; }
    public string State { get; set; } = "";
    public int DangerType { get; set; }
    public long ReceivedBytes { get; set; }
    public long TotalBytes { get; set; }
    public bool Opened { get; set; }
    public string SourceUrl { get; set; } = "";
    public string FinalUrl { get; set; } = "";
    public string ReferrerUrl { get; set; } = "";
    public string SiteUrl { get; set; } = "";
    public string PageUrl { get; set; } = "";
    public string HttpMethod { get; set; } = "";
    public string InitiatedByExtension { get; set; } = "";
    public string MimeType { get; set; } = "";
    public string DatabaseSource { get; set; } = "";
    public List<string> UrlChain { get; set; } = new();

    // Internal correlation key for Firefox; retained in JSON only as harmless metadata.
    public long? FirefoxPlaceId { get; set; }
}
