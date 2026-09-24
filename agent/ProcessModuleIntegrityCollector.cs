using System.Diagnostics;

namespace Vorken.Agent;

internal static class ProcessModuleIntegrityCollector
{
    private static readonly string[] HighValueProcesses =
    {
        "rust",
        "rustclient",
        "steam",
        "steamwebhelper",
        "explorer",
        "dwm",
        "lsass",
        "csrss",
        "services",
        "winlogon",
        "svchost"
    };

    public static List<ProcessModuleIntegrityRecord> Collect()
    {
        var result = new List<ProcessModuleIntegrityRecord>();

        string user =
            Environment.GetFolderPath(
                Environment.SpecialFolder.UserProfile);

        string temp =
            Path.GetTempPath();

        foreach (Process process in Process.GetProcesses())
        {
            try
            {
                bool highValue =
                    HighValueProcesses.Contains(
                        process.ProcessName,
                        StringComparer.OrdinalIgnoreCase);

                if (!highValue)
                    continue;

                string mainPath = "";

                try
                {
                    mainPath =
                        process.MainModule?.FileName ?? "";
                }
                catch
                {
                }

                bool mainSigned = false;
                string mainSigner = "";

                if (
                    !string.IsNullOrWhiteSpace(mainPath) &&
                    File.Exists(mainPath))
                {
                    (mainSigned, mainSigner) =
                        AuthenticodeVerifier.Verify(
                            mainPath);
                }

                foreach (ProcessModule module in process.Modules)
                {
                    try
                    {
                        string modulePath =
                            module.FileName ?? "";

                        if (string.IsNullOrWhiteSpace(modulePath))
                            continue;

                        bool underUser =
                            IsPathUnder(
                                modulePath,
                                user);

                        bool underTemp =
                            IsPathUnder(
                                modulePath,
                                temp);

                        bool underMainDirectory =
                            !string.IsNullOrWhiteSpace(mainPath) &&
                            IsPathUnder(
                                modulePath,
                                Path.GetDirectoryName(mainPath) ?? "");

                        if (
                            !underUser &&
                            !underTemp)
                        {
                            continue;
                        }

                        (bool signed, string signer) =
                            AuthenticodeVerifier.Verify(
                                modulePath);

                        bool suspicious =
                            !signed &&
                            !underMainDirectory;

                        if (!suspicious)
                            continue;

                        result.Add(
                            new ProcessModuleIntegrityRecord
                            {
                                ProcessId = process.Id,
                                ProcessName =
                                    process.ProcessName,
                                ProcessPath = mainPath,
                                ProcessSigned = mainSigned,
                                ProcessSigner = mainSigner,
                                ModuleName =
                                    module.ModuleName ??
                                    Path.GetFileName(modulePath),
                                ModulePath = modulePath,
                                ModuleSigned = signed,
                                ModuleSigner = signer,
                                UnderUserProfile = underUser,
                                UnderTemp = underTemp,
                                UnderProcessDirectory =
                                    underMainDirectory,
                                Suspicious = true
                            });
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }
            finally
            {
                process.Dispose();
            }
        }

        return result
            .GroupBy(
                x =>
                    $"{x.ProcessId}|{x.ModulePath}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(1200)
            .ToList();
    }

    private static bool IsPathUnder(
        string path,
        string root)
    {
        if (
            string.IsNullOrWhiteSpace(path) ||
            string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        try
        {
            string fullPath =
                Path.GetFullPath(path);

            string fullRoot =
                Path.GetFullPath(root)
                    .TrimEnd(
                        Path.DirectorySeparatorChar) +
                Path.DirectorySeparatorChar;

            return fullPath.StartsWith(
                fullRoot,
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}

internal sealed class ProcessModuleIntegrityRecord
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    public bool ProcessSigned { get; set; }
    public string ProcessSigner { get; set; } = "";
    public string ModuleName { get; set; } = "";
    public string ModulePath { get; set; } = "";
    public bool ModuleSigned { get; set; }
    public string ModuleSigner { get; set; } = "";
    public bool UnderUserProfile { get; set; }
    public bool UnderTemp { get; set; }
    public bool UnderProcessDirectory { get; set; }
    public bool Suspicious { get; set; }
}
