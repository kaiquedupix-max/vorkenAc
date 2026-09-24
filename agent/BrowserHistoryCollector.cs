using Microsoft.Data.Sqlite;
using System.Globalization;

namespace Vorken.Agent;

internal static class BrowserHistoryCollector
{
    private static readonly DateTime ChromiumEpoch =
        new(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static readonly string[] StrongPhrases =
    {
        "rust cheat",
        "rust hack",
        "rust script",
        "recoil script",
        "no recoil",
        "aimbot",
        "wallhack",
        "silent aim",
        "ragebot",
        "triggerbot",
        "cheat loader",
        "hack loader",
        "external cheat",
        "internal cheat",
        "undetected cheat",
        "hwid spoofer",
        "eac bypass",
        "easy anti cheat bypass",
        "rust injector"
    };

    private static readonly string[] KnownRustCheatBrands =
    {
        "lethality rust",
        "lethality script",
        "lethality club",
        "revolex",
        "revolex script",
        "purge recoil",
        "purge rust",
        "zaza cheats",
        "zaza private",
        "slayer rust",
        "slayer private",
        "disconnect cheats",
        "beazt private",
        "beazt rust",
        "agera rust",
        "pure dma rust",
        "lordcheat",
        "aimsync rust",
        "rust smartai",
        "nowax cheats",
        "fcheats rust",
        "memez macros",
        "memez internalx",
        "memez external",
        "gamevantage rust",
        "blastaim rust",
        "auroracheats",
        "aegis rust cheat",
        "mirage rust external",
        "the darkest magic",
        "moonlight rust",
        "moonlight script",
        "poak rust",
        "poak script",
        "revelx",
        "revelx rust",
        "aimmy rust",
        "kosmos aimbot",
        "synthar aimbot",
        "lethality.club",
        "revolexscript.com",
        "purgerecoil.club",
        "zazacheats.net",
        "slayer.club",
        "disconnectcheats.com",
        "nowaxcheats.com",
        "fcheats.com",
        "aimsync.ai",
        "aptitude.pub",
        "discord.gg/lethalityrust",
        "discord.gg/zazacheats",
        "discord.gg/j4gp9t",
        "discord.me/zbscn"
    };

    private static readonly string[] ContextTerms =
    {
        "cheat",
        "hack",
        "script",
        "loader",
        "injector",
        "aimbot",
        "wallhack",
        "esp",
        "recoil",
        "macro",
        "bypass",
        "spoofer",
        "exploit"
    };

    private static readonly string[] GameTerms =
    {
        "rust",
        "facepunch",
        "eac",
        "easy anti cheat",
        "easyanticheat"
    };

    private static readonly string[] BenignPhrases =
    {
        "anti-cheat",
        "anticheat",
        "anti cheat",
        "cheat sheet",
        "cheatsheet"
    };

    public static List<BrowserHistoryRecord> CollectSuspicious(
        IEnumerable<RustThreatIndicator>? threatCatalog = null)
    {
        var result = new List<BrowserHistoryRecord>();
        IReadOnlyCollection<string> catalogTerms =
            BuildCatalogTerms(threatCatalog);

        foreach (HistoryProfile profile in EnumerateChromiumProfiles())
        {
            try
            {
                result.AddRange(ReadChromium(profile, catalogTerms));
            }
            catch
            {
            }
        }

        foreach (HistoryProfile profile in EnumerateFirefoxProfiles())
        {
            try
            {
                result.AddRange(ReadFirefox(profile, catalogTerms));
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
                    x.Url,
                    x.VisitTimeUtc?.Ticks ?? 0),
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .OrderByDescending(x => x.VisitTimeUtc ?? DateTime.MinValue)
            .Take(1500)
            .ToList();
    }

    private static List<BrowserHistoryRecord> ReadChromium(HistoryProfile profile)
    {
        var result = new List<BrowserHistoryRecord>();
        string? snapshot = CreateSnapshot(profile.DatabasePath);
        if (snapshot is null) return result;

        try
        {
            using var connection = Open(snapshot);

            if (!TableExists(connection, "urls"))
                return result;

            bool hasVisits = TableExists(connection, "visits");

            using var command = connection.CreateCommand();

            command.CommandText = hasVisits
                ? @"SELECT
                        u.url,
                        u.title,
                        u.visit_count,
                        u.typed_count,
                        MAX(v.visit_time) AS last_visit
                    FROM urls u
                    LEFT JOIN visits v ON v.url = u.id
                    GROUP BY u.id
                    ORDER BY last_visit DESC
                    LIMIT 25000"
                : @"SELECT
                        url,
                        title,
                        visit_count,
                        typed_count,
                        last_visit_time
                    FROM urls
                    ORDER BY last_visit_time DESC
                    LIMIT 25000";

            using SqliteDataReader reader = command.ExecuteReader();

            while (reader.Read())
            {
                string url = GetString(reader, 0);
                string title = GetString(reader, 1);
                int visitCount = GetInt32(reader, 2);
                int typedCount = GetInt32(reader, 3);
                DateTime? visitTime = ChromiumTime(GetInt64(reader, 4));

                BrowserHistoryRecord? record = Evaluate(
                    profile.Browser,
                    profile.Profile,
                    url,
                    title,
                    visitTime,
                    visitCount,
                    typedCount,
                    "Chromium History/urls+visits",
                    catalogTerms);

                if (record is not null)
                    result.Add(record);
            }
        }
        finally
        {
            Cleanup(snapshot);
        }

        return result;
    }

    private static List<BrowserHistoryRecord> ReadFirefox(HistoryProfile profile)
    {
        var result = new List<BrowserHistoryRecord>();
        string? snapshot = CreateSnapshot(profile.DatabasePath);
        if (snapshot is null) return result;

        try
        {
            using var connection = Open(snapshot);

            if (!TableExists(connection, "moz_places"))
                return result;

            bool hasVisits = TableExists(connection, "moz_historyvisits");

            using var command = connection.CreateCommand();

            command.CommandText = hasVisits
                ? @"SELECT
                        p.url,
                        p.title,
                        p.visit_count,
                        p.typed,
                        MAX(h.visit_date) AS last_visit
                    FROM moz_places p
                    LEFT JOIN moz_historyvisits h ON h.place_id = p.id
                    GROUP BY p.id
                    ORDER BY last_visit DESC
                    LIMIT 25000"
                : @"SELECT
                        url,
                        title,
                        visit_count,
                        typed,
                        last_visit_date
                    FROM moz_places
                    ORDER BY last_visit_date DESC
                    LIMIT 25000";

            using SqliteDataReader reader = command.ExecuteReader();

            while (reader.Read())
            {
                string url = GetString(reader, 0);
                string title = GetString(reader, 1);
                int visitCount = GetInt32(reader, 2);
                int typedCount = GetInt32(reader, 3);
                DateTime? visitTime = FirefoxTime(GetInt64(reader, 4));

                BrowserHistoryRecord? record = Evaluate(
                    profile.Browser,
                    profile.Profile,
                    url,
                    title,
                    visitTime,
                    visitCount,
                    typedCount,
                    "Firefox places.sqlite",
                    catalogTerms);

                if (record is not null)
                    result.Add(record);
            }
        }
        finally
        {
            Cleanup(snapshot);
        }

        return result;
    }

    private static BrowserHistoryRecord? Evaluate(
        string browser,
        string profile,
        string url,
        string title,
        DateTime? visitTime,
        int visitCount,
        int typedCount,
        string source,
        IReadOnlyCollection<string> catalogTerms)
    {
        if (string.IsNullOrWhiteSpace(url))
            return null;

        string decodedUrl = SafeDecode(url);
        string searchQuery = ExtractSearchQuery(url);
        string host = ExtractHost(url);

        string combined =
            string.Join(
                " ",
                decodedUrl,
                title ?? "",
                searchQuery,
                host)
            .ToLowerInvariant();

        var matches = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);

        foreach (string phrase in StrongPhrases)
        {
            if (combined.Contains(phrase, StringComparison.OrdinalIgnoreCase))
                matches.Add(phrase);
        }

        foreach (string term in ContextTerms)
        {
            if (combined.Contains(term, StringComparison.OrdinalIgnoreCase))
                matches.Add(term);
        }

        bool knownBrand =
            KnownRustCheatBrands
                .Concat(catalogTerms)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Any(term =>
                {
                    if (string.IsNullOrWhiteSpace(term) ||
                        !combined.Contains(term, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    matches.Add(term);
                    return true;
                });

        bool hasGameTerm =
            GameTerms.Any(term =>
                combined.Contains(term, StringComparison.OrdinalIgnoreCase));

        bool hostOrUrlCheatSignal =
            !string.IsNullOrWhiteSpace(host) &&
            (
                host.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                host.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                decodedUrl.Contains("/cheat", StringComparison.OrdinalIgnoreCase) ||
                decodedUrl.Contains("/hack", StringComparison.OrdinalIgnoreCase)
            );

        bool benignOnly =
            BenignPhrases.Any(phrase =>
                combined.Contains(phrase, StringComparison.OrdinalIgnoreCase)) &&
            matches.Count <= 1 &&
            !hasGameTerm &&
            !hostOrUrlCheatSignal;

        if (benignOnly)
            return null;

        bool strong =
            knownBrand ||
            StrongPhrases.Any(phrase => matches.Contains(phrase));

        bool suspiciousSearch =
            !string.IsNullOrWhiteSpace(searchQuery) &&
            (
                strong ||
                hasGameTerm && matches.Count >= 1 ||
                matches.Count >= 2
            );

        bool suspiciousSite =
            hostOrUrlCheatSignal ||
            strong ||
            hasGameTerm && matches.Count >= 1;

        if (!suspiciousSearch && !suspiciousSite)
            return null;

        int score = 0;

        if (strong) score += 3;
        if (knownBrand) score += 3;
        if (hostOrUrlCheatSignal) score += 2;
        if (hasGameTerm) score += 1;
        if (suspiciousSearch) score += 2;
        if (matches.Count >= 2) score += 1;
        if (typedCount > 0) score += 1;

        string risk =
            score >= 5 ? "high" :
            score >= 3 ? "medium" :
            "low";

        string reason =
            knownBrand
                ? "Nome conhecido de software/comunidade de cheat/script para Rust"
                : suspiciousSearch
                    ? "Pesquisa/consulta relacionada a cheat/script/hack"
                    : hostOrUrlCheatSignal
                    ? "Site/URL com indicador explícito de cheat/hack"
                    : "Página relacionada a termos de cheat/script para Rust";

        return new BrowserHistoryRecord
        {
            Browser = browser,
            Profile = profile,
            Url = url,
            Host = host,
            Title = title ?? "",
            SearchQuery = searchQuery,
            VisitTimeUtc = visitTime,
            VisitCount = visitCount,
            TypedCount = typedCount,
            MatchedTerms = matches
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList(),
            RiskLevel = risk,
            RiskScore = score,
            Reason = reason,
            DatabaseSource = source
        };
    }

    private static IReadOnlyCollection<string> BuildCatalogTerms(
        IEnumerable<RustThreatIndicator>? threatCatalog)
    {
        var terms = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);

        if (threatCatalog is null)
            return terms;

        foreach (RustThreatIndicator item in threatCatalog)
        {
            foreach (string alias in item.Aliases ?? new List<string>())
            {
                string value = alias.Trim();
                if (!string.IsNullOrWhiteSpace(value))
                    terms.Add(value);
            }

            foreach (string domain in item.Domains ?? new List<string>())
            {
                string value = domain.Trim();
                if (!string.IsNullOrWhiteSpace(value))
                    terms.Add(value);
            }

            foreach (string invite in item.DiscordInvites ?? new List<string>())
            {
                string value = invite.Trim();
                if (string.IsNullOrWhiteSpace(value))
                    continue;

                terms.Add("discord.gg/" + value);
                terms.Add("discord.com/invite/" + value);
                terms.Add("discord.me/" + value);
            }
        }

        return terms;
    }

    private static string ExtractSearchQuery(string url)
    {
        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri))
                return "";

            var wanted = new HashSet<string>(
                new[]
                {
                    "q", "query", "search", "search_query",
                    "text", "p", "keyword", "keywords"
                },
                StringComparer.OrdinalIgnoreCase);

            string query = uri.Query.TrimStart('?');

            foreach (string part in query.Split(
                         '&',
                         StringSplitOptions.RemoveEmptyEntries))
            {
                string[] pieces = part.Split('=', 2);
                if (pieces.Length == 0)
                    continue;

                string key = Uri.UnescapeDataString(pieces[0].Replace('+', ' '));
                if (!wanted.Contains(key))
                    continue;

                string value = pieces.Length > 1
                    ? Uri.UnescapeDataString(pieces[1].Replace('+', ' '))
                    : "";

                if (!string.IsNullOrWhiteSpace(value))
                    return value.Trim();
            }
        }
        catch
        {
        }

        return "";
    }

    private static string ExtractHost(string url)
    {
        try
        {
            return Uri.TryCreate(url, UriKind.Absolute, out Uri? uri)
                ? uri.Host
                : "";
        }
        catch
        {
            return "";
        }
    }

    private static string SafeDecode(string value)
    {
        try { return Uri.UnescapeDataString(value.Replace('+', ' ')); }
        catch { return value; }
    }

    private static IEnumerable<HistoryProfile> EnumerateChromiumProfiles()
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
                    yield return new HistoryProfile
                    {
                        Browser = root.Browser,
                        Profile = Path.GetFileName(root.Path),
                        DatabasePath = history
                    };
                }

                continue;
            }

            IEnumerable<string> dirs;
            try { dirs = Directory.EnumerateDirectories(root.Path); }
            catch { continue; }

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

                yield return new HistoryProfile
                {
                    Browser = root.Browser,
                    Profile = name,
                    DatabasePath = history
                };
            }
        }
    }

    private static IEnumerable<HistoryProfile> EnumerateFirefoxProfiles()
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
        try { dirs = Directory.EnumerateDirectories(root); }
        catch { yield break; }

        foreach (string dir in dirs)
        {
            string db = Path.Combine(dir, "places.sqlite");
            if (!File.Exists(db))
                continue;

            yield return new HistoryProfile
            {
                Browser = "Mozilla Firefox",
                Profile = Path.GetFileName(dir),
                DatabasePath = db
            };
        }
    }

    private static string? CreateSnapshot(string source)
    {
        string? directory = null;

        try
        {
            directory = Path.Combine(
                Path.GetTempPath(),
                "Vorken",
                "BrowserHistoryDb",
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
                    CopyOpenFile(sidecar, destination + suffix);
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

    private static void CopyOpenFile(string source, string destination)
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

    private static bool TableExists(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$name LIMIT 1";
        command.Parameters.AddWithValue("$name", table);
        return command.ExecuteScalar() is not null;
    }

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
            return DateTime.UnixEpoch.AddTicks(
                checked(microseconds * 10L));
        }
        catch
        {
            return null;
        }
    }

    private static string GetString(SqliteDataReader reader, int ordinal)
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

    private static long GetInt64(SqliteDataReader reader, int ordinal)
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

    private static int GetInt32(SqliteDataReader reader, int ordinal)
    {
        long value = GetInt64(reader, ordinal);
        if (value > int.MaxValue) return int.MaxValue;
        if (value < int.MinValue) return int.MinValue;
        return (int)value;
    }

    private static void Cleanup(string path)
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
}

internal sealed class HistoryProfile
{
    public string Browser { get; set; } = "";
    public string Profile { get; set; } = "";
    public string DatabasePath { get; set; } = "";
}

internal sealed class BrowserHistoryRecord
{
    public string Browser { get; set; } = "";
    public string Profile { get; set; } = "";
    public string Url { get; set; } = "";
    public string Host { get; set; } = "";
    public string Title { get; set; } = "";
    public string SearchQuery { get; set; } = "";
    public DateTime? VisitTimeUtc { get; set; }
    public int VisitCount { get; set; }
    public int TypedCount { get; set; }
    public List<string> MatchedTerms { get; set; } = new();
    public string RiskLevel { get; set; } = "low";
    public int RiskScore { get; set; }
    public string Reason { get; set; } = "";
    public string DatabaseSource { get; set; } = "";
}
