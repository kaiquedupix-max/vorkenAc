using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Vorken.Agent;

internal static class WindowProtectionCollector
{
    private const uint WDA_NONE = 0x00000000;
    private const uint WDA_MONITOR = 0x00000001;
    private const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;

    public static List<WindowProtectionRecord> Collect()
    {
        var result = new List<WindowProtectionRecord>();

        EnumWindows(
            (hwnd, _) =>
            {
                try
                {
                    if (!IsWindowVisible(hwnd))
                        return true;

                    uint affinity = WDA_NONE;
                    bool affinityReadable =
                        GetWindowDisplayAffinity(
                            hwnd,
                            out affinity);

                    if (!affinityReadable ||
                        affinity == WDA_NONE)
                    {
                        return true;
                    }

                    _ = GetWindowThreadProcessId(
                        hwnd,
                        out uint pid);

                    string processName = "";
                    string processPath = "";
                    bool signed = false;
                    string signer = "";

                    try
                    {
                        using Process process =
                            Process.GetProcessById(checked((int)pid));

                        processName = process.ProcessName;

                        try
                        {
                            processPath =
                                process.MainModule?.FileName ?? "";

                            if (
                                !string.IsNullOrWhiteSpace(processPath) &&
                                File.Exists(processPath))
                            {
                                (signed, signer) =
                                    AuthenticodeVerifier.Verify(
                                        processPath);
                            }
                        }
                        catch
                        {
                        }
                    }
                    catch
                    {
                    }

                    var className = new StringBuilder(512);
                    _ = GetClassNameW(
                        hwnd,
                        className,
                        className.Capacity);

                    result.Add(new WindowProtectionRecord
                    {
                        ProcessId = pid,
                        ProcessName = processName,
                        ProcessPath = processPath,
                        Signed = signed,
                        SignerSubject = signer,
                        WindowClass = className.ToString(),
                        DisplayAffinity = affinity,
                        ExcludedFromCapture =
                            affinity == WDA_EXCLUDEFROMCAPTURE,
                        MonitorOnly =
                            affinity == WDA_MONITOR
                    });
                }
                catch
                {
                }

                return true;
            },
            IntPtr.Zero);

        return result
            .GroupBy(
                x => $"{x.ProcessId}|{x.WindowClass}|{x.DisplayAffinity}")
            .Select(x => x.First())
            .Take(1000)
            .ToList();
    }

    private delegate bool EnumWindowsProc(
        IntPtr hwnd,
        IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(
        EnumWindowsProc lpEnumFunc,
        IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(
        IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowDisplayAffinity(
        IntPtr hWnd,
        out uint pdwAffinity);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(
        IntPtr hWnd,
        out uint lpdwProcessId);

    [DllImport(
        "user32.dll",
        CharSet = CharSet.Unicode)]
    private static extern int GetClassNameW(
        IntPtr hWnd,
        StringBuilder lpClassName,
        int nMaxCount);
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
