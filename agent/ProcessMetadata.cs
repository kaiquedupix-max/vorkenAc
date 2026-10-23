using System.Management;
namespace Vorken.Agent;

internal static class ProcessMetadata
{
    public static string? TryGetExecutablePath(int pid)
    {
        try
        {
            // OS metadata query only; no MainModule/Modules or process-memory handle.
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId={pid} AND Name!='Rust.exe' AND Name!='RustClient.exe' AND Name!='RustDedicated.exe' AND NOT Name LIKE 'EasyAntiCheat%'");
            using var rows = searcher.Get();
            foreach (ManagementObject row in rows)
            {
                using (row) return row["ExecutablePath"] as string;
            }
        }
        catch { }
        return null;
    }
}
