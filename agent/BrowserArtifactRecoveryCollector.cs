using System.Text;
using System.Text.RegularExpressions;

namespace Vorken.Agent;

internal static class BrowserArtifactRecoveryCollector
{
    private static readonly Regex UrlRegex = new(
        @"https?://[^\s<>""'\x00]{6,1800}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RiskyFileRegex = new(
        @"(?<![A-Za-z0-9_.-])(" +
        @"[A-Za-z0-9_-]{4,64}\.(?:zip|rar|7z|pdf|jpg|jpeg|png|txt)\.exe" +
        @"|" +
        @"[A-Za-z0-9_.-]{4,100}\.(?:exe|com|scr|dll|msi|bat|cmd|ps1|zip|rar|7z)" +
        @")",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] ContextTerms =
    {
        "rust cheat",
        "rust hack",
        "rust script",
        "recoil script",
        "no recoil",
        "aimbot",
        "wallhack",
        "silent aim",
        "loader",
        "injector",
        "spoofer",
        "eac bypass",
        "easy anti cheat bypass",
        "discord.gg/",
        "cdn.discordapp.com/",
        "t.me/"
    };

    public static List<RecoveredBrowserArtifact> Collect(
        List<RustThreatIndicator> threatCatalog)
    {
        var result = new List<RecoveredBrowserArtifact>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (BrowserRawArtifact artifact in EnumerateArtifacts())
        {
            try
            {
                CarveArtifact(
                    artifact,
                    threatCatalog,
                    result,
                    seen);
            }
            catch
            {
            }

            if (result.Count >= 3000)
                break;
        }

        return result
            .OrderByDescending(x => x.RiskScore)
            .ThenBy(x => x.Browser)
            .Take(3000)
            .ToList();
    }

    private static void CarveArtifact(
        BrowserRawArtifact artifact,
        List<RustThreatIndicator> threatCatalog,
        List<RecoveredBrowserArtifact> target,
        HashSet<string> seen)
    {
        using var stream = new FileStream(
            artifact.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);

        const int maxBytes = 192 * 1024 * 1024;
        long start = Math.Max(0, stream.Length - maxBytes);
        stream.Position = start;

        byte[] buffer = new byte[4 * 1024 * 1024];
        var printable = new StringBuilder(4096);

        int read;

        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < read; i++)
            {
                byte b = buffer[i];

                if (b >= 0x20 && b <= 0x7E)
                {
                    if (printable.Length < 8192)
                        printable.Append((char)b);
                    else
                        FlushPrintable(
                            printable,
                            artifact,
                            threatCatalog,
                            target,
                            seen);
                }
                else
                {
                    FlushPrintable(
                        printable,
                        artifact,
                        threatCatalog,
                        target,
                        seen);
                }
            }

            if (target.Count >= 3000)
                break;
        }

        FlushPrintable(
            printable,
            artifact,
            threatCatalog,
            target,
            seen);
    }

    private static void FlushPrintable(
        StringBuilder printable,
        BrowserRawArtifact artifact,
        List<RustThreatIndicator> threatCatalog,
        List<RecoveredBrowserArtifact> target,
        HashSet<string> seen)
    {
        if (printable.Length < 8)
        {
            printable.Clear();
            return;
        }

        string text = printable.ToString();
        printable.Clear();

        foreach (Match match in UrlRegex.Matches(text))
        {
            string url = CleanUrl(match.Value);

            // Never let unrelated strings from the same raw SQLite page
            // contaminate a URL finding. The URL itself already contains
            // search queries, domains and paths needed for classification.
            AddCandidate(
                artifact,
                url: url,
                fileName: "",
                context: url,
                threatCatalog,
                target,
                seen);
        }

        foreach (Match match in RiskyFileRegex.Matches(text))
        {
            string fileName = match.Groups[1].Value;

            // For filenames keep only a small neighborhood. Raw SQLite pages
            // can contain thousands of unrelated URLs/strings.
            int start = Math.Max(0, match.Index - 192);
            int length = Math.Min(
                text.Length - start,
                match.Length + 384);

            string nearby = text.Substring(start, length);

            AddCandidate(
                artifact,
                url: "",
                fileName: fileName,
                context: nearby,
                threatCatalog,
                target,
                seen);
        }
    }

    private static void AddCandidate(
        BrowserRawArtifact artifact,
        string url,
        string fileName,
        string context,
        List<RustThreatIndicator> threatCatalog,
        List<RecoveredBrowserArtifact> target,
        HashSet<string> seen)
    {
        string candidateText =
            string.Join(
                " ",
                url,
                fileName)
            .ToLowerInvariant();

        string combined =
            string.Join(
                " ",
                candidateText,
                context)
            .ToLowerInvariant();

        List<string> catalogMatches =
            MatchCatalog(candidateText, threatCatalog);

        if (
            catalogMatches.Count == 0 &&
            !string.IsNullOrWhiteSpace(fileName))
        {
            catalogMatches =
                MatchCatalog(combined, threatCatalog);
        }

        List<string> matchedTerms = ContextTerms
            .Where(term =>
                combined.Contains(
                    term,
                    StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        bool randomExecutable =
            !string.IsNullOrWhiteSpace(fileName) &&
            LooksRandomExecutableName(fileName);

        bool doubleExtension =
            !string.IsNullOrWhiteSpace(fileName) &&
            Regex.IsMatch(
                fileName,
                @"\.(zip|rar|7z|pdf|jpg|jpeg|png|txt)\.exe$",
                RegexOptions.IgnoreCase);

        bool socialOrigin =
            combined.Contains("discord.gg/") ||
            combined.Contains("discord.com/") ||
            combined.Contains("cdn.discordapp.com/") ||
            combined.Contains("discordapp.com/") ||
            combined.Contains("t.me/") ||
            combined.Contains("telegram.org/");

        bool suspicious =
            catalogMatches.Count > 0 ||
            randomExecutable ||
            doubleExtension ||
            (
                matchedTerms.Count >= 2 &&
                (
                    combined.Contains("rust") ||
                    combined.Contains("eac") ||
                    combined.Contains("easy anti cheat")
                )
            ) ||
            (
                socialOrigin &&
                !string.IsNullOrWhiteSpace(fileName)
            );

        if (!suspicious)
            return;

        int score = 0;

        if (catalogMatches.Count > 0) score += 5;
        if (randomExecutable) score += 5;
        if (doubleExtension) score += 4;
        if (socialOrigin) score += 2;
        if (matchedTerms.Count >= 2) score += 2;
        if (artifact.IsSidecar) score += 1;

        string key =
            $"{artifact.Browser}|{artifact.Profile}|{url}|{fileName}|{string.Join(",", catalogMatches)}";

        if (!seen.Add(key))
            return;

        target.Add(new RecoveredBrowserArtifact
        {
            Browser = artifact.Browser,
            Profile = artifact.Profile,
            SourceArtifact = Path.GetFileName(artifact.Path),
            SourcePath = artifact.Path,
            RecoveredUrl = url,
            RecoveredFileName = fileName,
            CatalogMatches = catalogMatches,
            MatchedTerms = matchedTerms,
            RandomLikeName = randomExecutable,
            DeceptiveDoubleExtension = doubleExtension,
            SocialOrigin = socialOrigin,
            RiskScore = score,
            RecoveryKind = artifact.IsSidecar
                ? "SQLite WAL/journal"
                : "SQLite raw pages",
            Note = artifact.IsSidecar
                ? "Recuperado de artefato transacional do navegador. Pode sobreviver após limpeza do histórico até ser sobrescrito."
                : "String recuperada diretamente das páginas do banco SQLite. Pode representar registro ativo ou remanescente não sobrescrito."
        });
    }

    private static List<string> MatchCatalog(
        string haystack,
        List<RustThreatIndicator> catalog)
    {
        var result = new List<string>();

        foreach (RustThreatIndicator entry in catalog)
        {
            bool matched =
                entry.Domains.Any(value =>
                    ContainsNeedle(haystack, value)) ||
                entry.DiscordInvites.Any(value =>
                    ContainsNeedle(
                        haystack,
                        "discord.gg/" + value)) ||
                entry.Aliases.Any(value =>
                {
                    string needle = StringValue(value);
                    return IsDistinctiveCatalogAlias(needle) &&
                           ContainsNeedle(haystack, needle);
                });

            if (matched)
                result.Add(entry.Name);

            if (result.Count >= 20)
                break;
        }

        return result;
    }

    private static bool IsDistinctiveCatalogAlias(string value)
    {
        string alias = StringValue(value);

        if (alias.Length >= 7)
            return true;

        return
            alias.Contains("rust") ||
            alias.Contains("cheat") ||
            alias.Contains("script") ||
            alias.Contains("aimbot") ||
            alias.Contains("recoil") ||
            alias.Contains("loader") ||
            alias.Contains("private") ||
            alias.Contains("dma") ||
            alias.Contains("external") ||
            alias.Contains("internal");
    }

    private static bool ContainsNeedle(
        string haystack,
        string? value)
    {
        string needle = StringValue(value);
        if (needle.Length < 4)
            return false;

        int start = 0;

        while (start <= haystack.Length - needle.Length)
        {
            int index = haystack.IndexOf(
                needle,
                start,
                StringComparison.OrdinalIgnoreCase);

            if (index < 0)
                return false;

            int end = index + needle.Length;

            bool leftOk =
                index == 0 ||
                !char.IsLetterOrDigit(haystack[index - 1]);

            bool rightOk =
                end == haystack.Length ||
                !char.IsLetterOrDigit(haystack[end]);

            if (leftOk && rightOk)
                return true;

            start = index + 1;
        }

        return false;
    }

    private static string StringValue(string? value) =>
        (value ?? "").Trim().ToLowerInvariant();

    private static string CleanUrl(string value)
    {
        string result = value;

        int cut = result.IndexOfAny(
            new[] { ')', ']', '}', ',', ';' });

        if (cut > 8)
            result = result[..cut];

        return result.TrimEnd('.', ':');
    }

    private static bool LooksRandomExecutableName(string value)
    {
        if (!Path.GetExtension(value)
                .Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string stem = Path.GetFileNameWithoutExtension(value);

        if (
            IsGenericInstallerStem(stem) ||
            HasReadableExecutableToken(stem))
        {
            return false;
        }

        stem = Regex.Replace(
            stem,
            @"\.(zip|rar|7z|pdf|jpg|jpeg|png|txt)$",
            "",
            RegexOptions.IgnoreCase);

        if (stem.Length < 4 || stem.Length > 28 ||
            !stem.All(char.IsLetterOrDigit))
        {
            return false;
        }

        int letters = stem.Count(char.IsLetter);
        int digits = stem.Count(char.IsDigit);
        int vowels = stem.Count(ch => "aeiouAEIOU".Contains(ch));
        int distinct = stem.ToUpperInvariant().Distinct().Count();

        bool allUpperOrDigits = stem.All(ch =>
            char.IsDigit(ch) || char.IsUpper(ch));

        double vowelRatio = letters > 0
            ? (double)vowels / letters
            : 0;

        if (stem.Length <= 5)
        {
            return
                allUpperOrDigits &&
                distinct >= Math.Max(4, stem.Length - 1) &&
                (digits >= 1 || vowels == 0) &&
                vowelRatio <= 0.25;
        }

        if (
            allUpperOrDigits &&
            distinct >= Math.Min(6, stem.Length - 1) &&
            (
                digits >= 1
                    ? vowelRatio <= 0.35
                    : vowelRatio <= 0.12
            ))
        {
            return true;
        }

        if (
            stem.Length >= 8 &&
            stem.Length <= 18 &&
            digits == 0 &&
            letters == stem.Length &&
            distinct >= 7 &&
            vowelRatio <= 0.22)
        {
            return true;
        }

        int transitions = 0;
        for (int i = 1; i < stem.Length; i++)
        {
            bool previousDigit = char.IsDigit(stem[i - 1]);
            bool currentDigit = char.IsDigit(stem[i]);

            if (previousDigit != currentDigit)
                transitions++;
        }

        bool trailingDigitsOnly =
            Regex.IsMatch(
                stem,
                @"^[A-Za-z]+[0-9]{1,4}$");

        if (
            trailingDigitsOnly &&
            letters >= 5 &&
            vowelRatio >= 0.16)
        {
            return false;
        }

        return
            stem.Length >= 10 &&
            letters >= 6 &&
            digits >= 2 &&
            distinct >= 8 &&
            (
                transitions >= 3 ||
                vowelRatio <= 0.12
            );
    }

    private static bool IsGenericInstallerStem(string value)
    {
        string stem = (value ?? "").Trim().ToLowerInvariant();

        return stem is
            "installer" or
            "install" or
            "setup" or
            "setup64" or
            "setup32" or
            "updater" or
            "update" or
            "uninstall" or
            "uninstaller" or
            "bootstrapper" or
            "launcherinstaller";
    }

    private static bool HasReadableExecutableToken(string value)
    {
        string stem = (value ?? "")
            .ToLowerInvariant()
            .Replace("_", "")
            .Replace("-", "")
            .Replace(".", "");

        string[] tokens =
        {
            "installer", "install", "setup", "updater", "update",
            "uninstall", "bootstrapper", "launcher", "browser",
            "microsoft", "windows", "store", "opera", "avast",
            "crystal", "disk", "info", "control", "driver", "client",
            "helper", "service", "runtime", "manager", "discord",
            "chrome", "edge", "steam", "spotify", "firefox",
            "nvidia", "amd", "intel"
        };

        return tokens.Any(token =>
            token.Length >= 4 &&
            stem.Contains(token, StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<BrowserRawArtifact> EnumerateArtifacts()
    {
        string local = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);

        string roaming = Environment.GetFolderPath(
            Environment.SpecialFolder.ApplicationData);

        var chromiumRoots = new[]
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

        foreach (var root in chromiumRoots)
        {
            if (!Directory.Exists(root.Path))
                continue;

            if (root.RootIsProfile)
            {
                foreach (BrowserRawArtifact artifact in
                         BuildArtifacts(
                             root.Browser,
                             Path.GetFileName(root.Path),
                             Path.Combine(root.Path, "History")))
                {
                    yield return artifact;
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
                string profile = Path.GetFileName(dir);

                if (!profile.Equals("Default", StringComparison.OrdinalIgnoreCase) &&
                    !profile.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase) &&
                    !profile.Equals("Guest Profile", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (BrowserRawArtifact artifact in
                         BuildArtifacts(
                             root.Browser,
                             profile,
                             Path.Combine(dir, "History")))
                {
                    yield return artifact;
                }
            }
        }

        string firefoxRoot = Path.Combine(
            roaming,
            "Mozilla",
            "Firefox",
            "Profiles");

        if (Directory.Exists(firefoxRoot))
        {
            IEnumerable<string> dirs;

            try
            {
                dirs = Directory.EnumerateDirectories(firefoxRoot);
            }
            catch
            {
                dirs = Array.Empty<string>();
            }

            foreach (string dir in dirs)
            {
                string profile = Path.GetFileName(dir);

                foreach (BrowserRawArtifact artifact in
                         BuildArtifacts(
                             "Mozilla Firefox",
                             profile,
                             Path.Combine(dir, "places.sqlite")))
                {
                    yield return artifact;
                }
            }
        }
    }

    private static IEnumerable<BrowserRawArtifact> BuildArtifacts(
        string browser,
        string profile,
        string database)
    {
        foreach (string suffix in new[] { "", "-wal", "-journal" })
        {
            string path = database + suffix;

            if (!File.Exists(path))
                continue;

            yield return new BrowserRawArtifact
            {
                Browser = browser,
                Profile = profile,
                Path = path,
                IsSidecar = suffix.Length > 0
            };
        }
    }
}

internal sealed class BrowserRawArtifact
{
    public string Browser { get; set; } = "";
    public string Profile { get; set; } = "";
    public string Path { get; set; } = "";
    public bool IsSidecar { get; set; }
}

internal sealed class RecoveredBrowserArtifact
{
    public string Browser { get; set; } = "";
    public string Profile { get; set; } = "";
    public string SourceArtifact { get; set; } = "";
    public string SourcePath { get; set; } = "";
    public string RecoveredUrl { get; set; } = "";
    public string RecoveredFileName { get; set; } = "";
    public List<string> CatalogMatches { get; set; } = new();
    public List<string> MatchedTerms { get; set; } = new();
    public bool RandomLikeName { get; set; }
    public bool DeceptiveDoubleExtension { get; set; }
    public bool SocialOrigin { get; set; }
    public int RiskScore { get; set; }
    public string RecoveryKind { get; set; } = "";
    public string Note { get; set; } = "";
}
