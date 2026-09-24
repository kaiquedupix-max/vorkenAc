using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Vorken.Agent;

internal static class NetworkIndicatorCollector
{
    private static readonly string[] AuthDomains =
    {
        "keyauth.cc",
        "keyauth.win",
        "eauth.us.to"
    };

    public static List<NetworkIndicatorRecord> Collect(
        List<RustThreatIndicator> threatCatalog)
    {
        var result = new List<NetworkIndicatorRecord>();

        CollectDnsCache(
            threatCatalog,
            result);

        CollectTcpConnections(result);

        return result
            .GroupBy(
                x =>
                    $"{x.Source}|{x.ProcessId}|{x.Domain}|{x.RemoteAddress}|{x.RemotePort}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(3000)
            .ToList();
    }

    private static void CollectDnsCache(
        List<RustThreatIndicator> threatCatalog,
        List<NetworkIndicatorRecord> result)
    {
        string output = Run(
            "ipconfig.exe",
            "/displaydns",
            12000);

        if (string.IsNullOrWhiteSpace(output))
            return;

        string currentName = "";

        foreach (string raw in output.Split(
                     new[] { "\r\n", "\n" },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            string line = raw.Trim();

            Match nameMatch = Regex.Match(
                line,
                @"^(Record Name|Nome do Registro)\s*\.\s*:\s*(.+)$",
                RegexOptions.IgnoreCase);

            if (nameMatch.Success)
            {
                currentName =
                    nameMatch.Groups[2].Value.Trim().TrimEnd('.');

                AddDnsIfInteresting(
                    currentName,
                    threatCatalog,
                    result);

                continue;
            }

            if (
                currentName.Length == 0 &&
                LooksLikeDomain(line))
            {
                AddDnsIfInteresting(
                    line.Trim().TrimEnd('.'),
                    threatCatalog,
                    result);
            }
        }
    }

    private static void AddDnsIfInteresting(
        string domain,
        List<RustThreatIndicator> threatCatalog,
        List<NetworkIndicatorRecord> result)
    {
        string lower = domain.ToLowerInvariant();

        var matches = new List<string>();

        foreach (string known in AuthDomains)
        {
            if (
                lower.Equals(
                    known,
                    StringComparison.OrdinalIgnoreCase) ||
                lower.EndsWith(
                    "." + known,
                    StringComparison.OrdinalIgnoreCase))
            {
                matches.Add(known);
            }
        }

        foreach (RustThreatIndicator entry in threatCatalog)
        {
            foreach (string raw in entry.Domains)
            {
                string needle = (raw ?? "")
                    .Trim()
                    .TrimEnd('.')
                    .ToLowerInvariant();

                if (needle.Length < 4)
                    continue;

                if (
                    lower.Equals(
                        needle,
                        StringComparison.OrdinalIgnoreCase) ||
                    lower.EndsWith(
                        "." + needle,
                        StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add(entry.Name);
                }
            }
        }

        if (matches.Count == 0)
            return;

        result.Add(new NetworkIndicatorRecord
        {
            Source = "DNS Cache",
            Domain = domain,
            MatchedIndicators = matches
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(20)
                .ToList(),
            Note =
                "Entrada encontrada no cache DNS do Windows. Não atribui, por si só, a consulta a um processo específico."
        });
    }

    private static void CollectTcpConnections(
        List<NetworkIndicatorRecord> result)
    {
        int size = 0;

        uint first = GetExtendedTcpTable(
            IntPtr.Zero,
            ref size,
            true,
            2,
            TcpTableClass.TCP_TABLE_OWNER_PID_ALL,
            0);

        if (
            first != 122 &&
            size <= 0)
        {
            return;
        }

        IntPtr buffer = Marshal.AllocHGlobal(size);

        try
        {
            uint status = GetExtendedTcpTable(
                buffer,
                ref size,
                true,
                2,
                TcpTableClass.TCP_TABLE_OWNER_PID_ALL,
                0);

            if (status != 0)
                return;

            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr =
                IntPtr.Add(buffer, 4);

            int rowSize =
                Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < count && i < 5000; i++)
            {
                MIB_TCPROW_OWNER_PID row =
                    Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                        rowPtr);

                rowPtr = IntPtr.Add(
                    rowPtr,
                    rowSize);

                if (
                    row.dwState != 5 &&
                    row.dwState != 2)
                {
                    continue;
                }

                string remoteAddress =
                    new IPAddress(row.dwRemoteAddr)
                        .ToString();

                int remotePort =
                    Port(row.dwRemotePort);

                if (
                    remotePort <= 0 ||
                    remoteAddress == "0.0.0.0")
                {
                    continue;
                }

                string processName = "";
                string processPath = "";
                bool signed = false;
                string signer = "";

                try
                {
                    using Process process =
                        Process.GetProcessById(
                            checked((int)row.dwOwningPid));

                    processName =
                        process.ProcessName;

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

                result.Add(new NetworkIndicatorRecord
                {
                    Source = "TCP",
                    ProcessId = row.dwOwningPid,
                    ProcessName = processName,
                    ProcessPath = processPath,
                    ProcessSigned = signed,
                    ProcessSigner = signer,
                    RemoteAddress = remoteAddress,
                    RemotePort = remotePort,
                    State = row.dwState.ToString()
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int Port(uint value)
    {
        byte[] bytes = BitConverter.GetBytes(value);
        return (bytes[0] << 8) + bytes[1];
    }

    private static bool LooksLikeDomain(string value)
    {
        return Regex.IsMatch(
            value,
            @"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$");
    }

    private static string Run(
        string fileName,
        string arguments,
        int timeoutMs)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using Process? process =
                Process.Start(psi);

            if (process == null)
                return "";

            string stdout =
                process.StandardOutput.ReadToEnd();

            _ = process.StandardError.ReadToEnd();

            if (!process.WaitForExit(timeoutMs))
            {
                try { process.Kill(true); } catch { }
                return "";
            }

            return process.ExitCode == 0
                ? stdout
                : "";
        }
        catch
        {
            return "";
        }
    }

    private enum TcpTableClass
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [DllImport(
        "iphlpapi.dll",
        SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        TcpTableClass tblClass,
        uint reserved);
}

internal sealed class NetworkIndicatorRecord
{
    public string Source { get; set; } = "";
    public uint ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    public bool ProcessSigned { get; set; }
    public string ProcessSigner { get; set; } = "";
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public string State { get; set; } = "";
    public string Domain { get; set; } = "";
    public List<string> MatchedIndicators { get; set; } = new();
    public string Note { get; set; } = "";
}
