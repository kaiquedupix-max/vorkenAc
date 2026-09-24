using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Vorken.Agent;

internal static class ProcessMemoryIntegrityCollector
{
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;

    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;

    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_GUARD = 0x100;

    private static readonly string[] TargetProcesses =
    {
        "rust",
        "rustclient",
        "steam",
        "steamwebhelper",
        "explorer"
    };

    public static List<ProcessMemoryIntegrityRecord> Collect()
    {
        var result = new List<ProcessMemoryIntegrityRecord>();

        GetNativeSystemInfo(out SYSTEM_INFO systemInfo);

        nuint minAddress =
            unchecked((nuint)systemInfo.lpMinimumApplicationAddress);

        nuint maxAddress =
            unchecked((nuint)systemInfo.lpMaximumApplicationAddress);

        foreach (Process process in Process.GetProcesses())
        {
            try
            {
                if (!TargetProcesses.Contains(
                        process.ProcessName,
                        StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                using SafeProcessHandle handle =
                    OpenProcess(
                        PROCESS_QUERY_INFORMATION |
                        PROCESS_VM_READ,
                        false,
                        process.Id);

                if (handle.IsInvalid)
                    continue;

                string processPath = "";

                try
                {
                    processPath =
                        process.MainModule?.FileName ?? "";
                }
                catch
                {
                }

                bool processSigned = false;
                string processSigner = "";

                if (
                    !string.IsNullOrWhiteSpace(processPath) &&
                    File.Exists(processPath))
                {
                    (processSigned, processSigner) =
                        AuthenticodeVerifier.Verify(processPath);
                }

                nuint address = minAddress;
                int inspectedRegions = 0;

                while (
                    address < maxAddress &&
                    inspectedRegions < 200000 &&
                    result.Count < 1000)
                {
                    inspectedRegions++;

                    nuint querySize =
                        VirtualQueryEx(
                            handle,
                            (IntPtr)address,
                            out MEMORY_BASIC_INFORMATION mbi,
                            (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());

                    if (querySize == 0)
                        break;

                    nuint baseAddress =
                        unchecked((nuint)mbi.BaseAddress);

                    nuint regionSize =
                        mbi.RegionSize;

                    if (regionSize == 0)
                        break;

                    bool committed =
                        mbi.State == MEM_COMMIT;

                    bool privateMemory =
                        mbi.Type == MEM_PRIVATE;

                    bool executable =
                        IsExecutableProtection(mbi.Protect);

                    bool guarded =
                        (mbi.Protect & PAGE_GUARD) != 0;

                    if (
                        committed &&
                        privateMemory &&
                        executable &&
                        !guarded &&
                        regionSize >= 0x1000 &&
                        regionSize <= 512UL * 1024UL * 1024UL)
                    {
                        bool mzHeader =
                            HasMzHeader(
                                handle,
                                mbi.BaseAddress);

                        result.Add(new ProcessMemoryIntegrityRecord
                        {
                            ProcessId = process.Id,
                            ProcessName = process.ProcessName,
                            ProcessPath = processPath,
                            ProcessSigned = processSigned,
                            ProcessSigner = processSigner,
                            BaseAddress =
                                "0x" + baseAddress.ToString("X"),
                            RegionSize =
                                checked((ulong)regionSize),
                            Protection = mbi.Protect,
                            MemoryType = "MEM_PRIVATE",
                            Executable = true,
                            MzHeader = mzHeader,
                            PotentialManualMap = mzHeader
                        });
                    }

                    nuint nextAddress =
                        baseAddress + regionSize;

                    if (nextAddress <= address)
                        break;

                    address = nextAddress;
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
                    $"{x.ProcessId}|{x.BaseAddress}|{x.RegionSize}")
            .Select(x => x.First())
            .Take(1000)
            .ToList();
    }

    private static bool HasMzHeader(
        SafeProcessHandle process,
        IntPtr address)
    {
        try
        {
            byte[] header = new byte[2];

            if (!ReadProcessMemory(
                    process,
                    address,
                    header,
                    header.Length,
                    out nuint read))
            {
                return false;
            }

            return
                read >= 2 &&
                header[0] == (byte)'M' &&
                header[1] == (byte)'Z';
        }
        catch
        {
            return false;
        }
    }

    private static bool IsExecutableProtection(
        uint protection)
    {
        uint baseProtection =
            protection & 0xFF;

        return
            baseProtection == PAGE_EXECUTE ||
            baseProtection == PAGE_EXECUTE_READ ||
            baseProtection == PAGE_EXECUTE_READWRITE ||
            baseProtection == PAGE_EXECUTE_WRITECOPY;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nuint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public nuint dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    private sealed class SafeProcessHandle
        : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeProcessHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle() =>
            CloseHandle(handle);
    }

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        int dwProcessId);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern nuint VirtualQueryEx(
        SafeProcessHandle hProcess,
        IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer,
        nuint dwLength);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(
        SafeProcessHandle hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int nSize,
        out nuint lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern void GetNativeSystemInfo(
        out SYSTEM_INFO lpSystemInfo);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(
        IntPtr hObject);
}

internal sealed class ProcessMemoryIntegrityRecord
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    public bool ProcessSigned { get; set; }
    public string ProcessSigner { get; set; } = "";
    public string BaseAddress { get; set; } = "";
    public ulong RegionSize { get; set; }
    public uint Protection { get; set; }
    public string MemoryType { get; set; } = "";
    public bool Executable { get; set; }
    public bool MzHeader { get; set; }
    public bool PotentialManualMap { get; set; }
}
