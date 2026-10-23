using System.IO.Enumeration;

namespace Vorken.Agent;

// One boundary for every collector: never open Rust processes or game storage.
internal static class InspectionScope
{
    public static bool IsExcludedProcess(string? name)
    {
        string stem = Path.GetFileNameWithoutExtension(name ?? "");
        return stem.Equals("rust", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("rustclient", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("rustdedicated", StringComparison.OrdinalIgnoreCase) ||
            stem.StartsWith("EasyAntiCheat", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly Lazy<string[]> RegisteredRustRoots = new(ReadRegisteredRustRoots);

    public static bool CanInspectPath(string? path) => CanInspectPath(path, RegisteredRustRoots.Value);

    internal static bool CanInspectPath(string? path, IEnumerable<string> excludedRoots)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            string fullPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
            // Reject device/UNC paths and reparse points so aliases cannot bypass exclusions.
            if (fullPath.StartsWith(@"\\", StringComparison.Ordinal)) return false;
            foreach (string part in fullPath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
            {
                string component = part.Split(':')[0].TrimEnd(' ', '.');
                // Skip DOS short-name aliases rather than resolve them inside protected storage.
                if (System.Text.RegularExpressions.Regex.IsMatch(component, @"~[0-9]+(?:\.|$)")) return false;
                if (component.Equals("steamapps", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("252490", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("Facepunch Studios", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("Rust", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("RustClient", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("RustDedicated", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("Rust_Data", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("RustClient_Data", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("RustDedicated_Data", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("Rust.exe", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("RustClient.exe", StringComparison.OrdinalIgnoreCase) ||
                    component.Equals("RustDedicated.exe", StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            foreach (string root in excludedRoots)
            {
                string normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
                if (fullPath.Equals(normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
                    fullPath.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            string? current = fullPath;
            while (!string.IsNullOrEmpty(current))
            {
                try
                {
                    if ((System.IO.File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                        return false;
                }
                catch (FileNotFoundException) { }
                catch (DirectoryNotFoundException) { }
                current = Path.GetDirectoryName(current);
            }
            return true;
        }
        catch { return false; }
    }

    private static string[] ReadRegisteredRustRoots()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows()) return Array.Empty<string>();
        foreach (var hive in new[] { Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryHive.CurrentUser })
        foreach (var view in new[] { Microsoft.Win32.RegistryView.Registry32, Microsoft.Win32.RegistryView.Registry64 })
        {
            try
            {
                using var registry = Microsoft.Win32.RegistryKey.OpenBaseKey(hive, view);
                using var key = registry.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 252490");
                if (key?.GetValue("InstallLocation") is string location && !string.IsNullOrWhiteSpace(location))
                    roots.Add(Path.GetFullPath(Environment.ExpandEnvironmentVariables(location.Trim('"'))));
            }
            catch { }
        }
        return roots.ToArray();
    }

    public static string RequirePath(string path)
    {
        if (!CanInspectPath(path))
            throw new UnauthorizedAccessException("Path excluded from inspection.");
        return path;
    }
}

// Read operations and traversal use the same boundary, including rule-provided paths.
internal static class ScanFile
{
    public static bool Exists(string? path) => InspectionScope.CanInspectPath(path) && System.IO.File.Exists(path);
    public static string ReadAllText(string path) => System.IO.File.ReadAllText(InspectionScope.RequirePath(path));
    public static byte[] ReadAllBytes(string path) => System.IO.File.ReadAllBytes(InspectionScope.RequirePath(path));
    public static string[] ReadAllLines(string path) => System.IO.File.ReadAllLines(InspectionScope.RequirePath(path));
    public static IEnumerable<string> ReadLines(string path) => System.IO.File.ReadLines(InspectionScope.RequirePath(path));
    public static FileStream OpenRead(string path) => System.IO.File.OpenRead(InspectionScope.RequirePath(path));
    public static DateTime GetLastWriteTimeUtc(string path) => System.IO.File.GetLastWriteTimeUtc(InspectionScope.RequirePath(path));
    public static void WriteAllText(string path, string contents) => System.IO.File.WriteAllText(InspectionScope.RequirePath(path), contents);
}

internal static class ScanDirectory
{
    public static bool Exists(string? path) => InspectionScope.CanInspectPath(path) && System.IO.Directory.Exists(path);
    public static DirectoryInfo CreateDirectory(string path) => System.IO.Directory.CreateDirectory(InspectionScope.RequirePath(path));
    public static void Delete(string path, bool recursive) => System.IO.Directory.Delete(InspectionScope.RequirePath(path), recursive);
    public static DateTime GetLastWriteTimeUtc(string path) => System.IO.Directory.GetLastWriteTimeUtc(InspectionScope.RequirePath(path));
    public static IEnumerable<string> EnumerateDirectories(string path) =>
        !InspectionScope.CanInspectPath(path) ? Array.Empty<string>() :
        System.IO.Directory.EnumerateDirectories(path).Where(InspectionScope.CanInspectPath);
    public static IEnumerable<string> EnumerateFiles(string path) => EnumerateFiles(path, "*", SearchOption.TopDirectoryOnly);
    public static IEnumerable<string> EnumerateFiles(string path, string pattern, SearchOption option) =>
        EnumerateFiles(path, pattern, new EnumerationOptions
        {
            RecurseSubdirectories = option == SearchOption.AllDirectories,
            IgnoreInaccessible = false,
            AttributesToSkip = 0,
            MatchType = MatchType.Win32
        });
    public static IEnumerable<string> EnumerateFiles(string path, string pattern, EnumerationOptions options)
    {
        var pending = new Stack<(string Path, int Depth)>();
        pending.Push((path, 0));
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            if (!InspectionScope.CanInspectPath(current.Path)) continue;
            // Materialize inside the try so deferred enumeration failures are handled too.
            string[] entries;
            try
            {
                entries = System.IO.Directory.EnumerateFileSystemEntries(current.Path, "*", new EnumerationOptions
                {
                    IgnoreInaccessible = options.IgnoreInaccessible,
                    AttributesToSkip = options.AttributesToSkip | FileAttributes.ReparsePoint,
                    ReturnSpecialDirectories = false
                }).ToArray();
            }
            catch (UnauthorizedAccessException) when (options.IgnoreInaccessible) { continue; }
            catch (IOException) when (options.IgnoreInaccessible) { continue; }
            foreach (string entry in entries)
            {
                if (!InspectionScope.CanInspectPath(entry)) continue;
                FileAttributes attributes;
                try { attributes = System.IO.File.GetAttributes(entry); }
                catch (UnauthorizedAccessException) when (options.IgnoreInaccessible) { continue; }
                catch (IOException) when (options.IgnoreInaccessible) { continue; }
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if (options.RecurseSubdirectories && current.Depth < options.MaxRecursionDepth)
                        pending.Push((entry, current.Depth + 1));
                }
                else
                {
                    bool ignoreCase = options.MatchCasing != MatchCasing.CaseSensitive;
                    bool matches = options.MatchType == MatchType.Win32
                        ? FileSystemName.MatchesWin32Expression(pattern, Path.GetFileName(entry), ignoreCase)
                        : FileSystemName.MatchesSimpleExpression(pattern, Path.GetFileName(entry), ignoreCase);
                    if (matches) yield return entry;
                }
            }
        }
    }
}
