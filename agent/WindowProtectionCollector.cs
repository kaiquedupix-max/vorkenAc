namespace Vorken.Agent;

// Screen inspection was removed; retain an empty legacy payload contract.
internal static class WindowProtectionCollector
{
    public static List<WindowProtectionRecord> Collect() => new();
}

internal sealed class WindowProtectionRecord
{
    public uint ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    public bool Signed { get; set; }
    public string SignerSubject { get; set; } = "";
    public string WindowClass { get; set; } = "";
    public uint DisplayAffinity { get; set; }
    public bool ExcludedFromCapture { get; set; }
    public bool MonitorOnly { get; set; }
}
