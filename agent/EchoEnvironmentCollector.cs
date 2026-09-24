using System.Management;
using System.Text;

namespace Vorken.Agent;

internal static class EchoEnvironmentCollector
{
    public static List<RecycleBinRecord> CollectRecycleBin()
    {
        var result = new List<RecycleBinRecord>();

        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady)
                    continue;

                string root = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
                if (!Directory.Exists(root))
                    continue;

                foreach (string sidDirectory in SafeDirectories(root).Take(200))
                {
                    foreach (string infoPath in SafeFiles(sidDirectory, "$I*").Take(3000))
                    {
                        if (result.Count >= 5000)
                            return result;

                        RecycleBinRecord? record = TryParseRecycleInfo(infoPath);
                        if (record is not null)
                            result.Add(record);
                    }
                }
            }
            catch
            {
            }
        }

        return result
            .OrderByDescending(x => x.DeletedAtUtc ?? DateTime.MinValue)
            .Take(5000)
            .ToList();
    }

    public static VmEnvironmentRecord CollectVmEnvironment()
    {
        var result = new VmEnvironmentRecord();

        try
        {
            using var systemSearcher = new ManagementObjectSearcher(
                "SELECT Manufacturer,Model FROM Win32_ComputerSystem");

            foreach (ManagementObject item in systemSearcher.Get())
            {
                result.Manufacturer = Convert.ToString(item["Manufacturer"]) ?? "";
                result.Model = Convert.ToString(item["Model"]) ?? "";
                break;
            }
        }
        catch
        {
        }

        try
        {
            using var biosSearcher = new ManagementObjectSearcher(
                "SELECT Manufacturer,SMBIOSBIOSVersion,SerialNumber FROM Win32_BIOS");

            foreach (ManagementObject item in biosSearcher.Get())
            {
                result.BiosManufacturer = Convert.ToString(item["Manufacturer"]) ?? "";
                result.BiosVersion = Convert.ToString(item["SMBIOSBIOSVersion"]) ?? "";
                break;
            }
        }
        catch
        {
        }

        string evidence = string.Join(
            " ",
            result.Manufacturer,
            result.Model,
            result.BiosManufacturer,
            result.BiosVersion)
            .ToLowerInvariant();

        string[] vmTokens =
        {
            "vmware",
            "virtualbox",
            "vbox",
            "qemu",
            "kvm",
            "xen",
            "parallels",
            "hyper-v",
            "virtual machine",
            "microsoft corporation virtual"
        };

        string? matched = vmTokens.FirstOrDefault(evidence.Contains);

        result.IsVirtualMachine = matched is not null;
        result.DetectedPlatform = matched switch
        {
            "vmware" => "VMware",
            "virtualbox" or "vbox" => "VirtualBox",
            "qemu" or "kvm" => "QEMU/KVM",
            "xen" => "Xen",
            "parallels" => "Parallels",
            "hyper-v" or "microsoft corporation virtual" => "Hyper-V",
            "virtual machine" => "Virtual Machine",
            _ => ""
        };

        return result;
    }

    private static RecycleBinRecord? TryParseRecycleInfo(string infoPath)
    {
        try
        {
            byte[] data = File.ReadAllBytes(infoPath);
            if (data.Length < 24)
                return null;

            long version = BitConverter.ToInt64(data, 0);
            long originalSize = BitConverter.ToInt64(data, 8);
            long deletedFileTime = BitConverter.ToInt64(data, 16);

            string originalPath = "";

            if (version >= 2 && data.Length >= 28)
            {
                int charCount = BitConverter.ToInt32(data, 24);

                if (charCount > 0 &&
                    charCount < 32768 &&
                    28 + charCount * 2 <= data.Length)
                {
                    originalPath = Encoding.Unicode
                        .GetString(data, 28, charCount * 2)
                        .TrimEnd('\0');
                }
            }

            if (string.IsNullOrWhiteSpace(originalPath) && data.Length > 24)
            {
                originalPath = Encoding.Unicode
                    .GetString(data, 24, data.Length - 24)
                    .TrimEnd('\0');
            }

            DateTime? deletedAt = null;
            try
            {
                if (deletedFileTime > 0)
                    deletedAt = DateTime.FromFileTimeUtc(deletedFileTime);
            }
            catch
            {
            }

            string infoFileName = Path.GetFileName(infoPath);
            string recycledName = infoFileName.Length >= 2
                ? "$R" + infoFileName[2..]
                : "";

            string recycledPath = string.IsNullOrWhiteSpace(recycledName)
                ? ""
                : Path.Combine(
                    Path.GetDirectoryName(infoPath) ?? "",
                    recycledName);

            return new RecycleBinRecord
            {
                OriginalPath = originalPath,
                FileName = SafeFileName(originalPath),
                DeletedAtUtc = deletedAt,
                OriginalSize = originalSize,
                InfoPath = infoPath,
                RecycledDataPath = recycledPath,
                RecycledDataPresent =
                    !string.IsNullOrWhiteSpace(recycledPath) &&
                    File.Exists(recycledPath),
                Version = version
            };
        }
        catch
        {
            return null;
        }
    }

    private static IEnumerable<string> SafeDirectories(string path)
    {
        try { return Directory.EnumerateDirectories(path).ToArray(); }
        catch { return Array.Empty<string>(); }
    }

    private static IEnumerable<string> SafeFiles(string path, string pattern)
    {
        try
        {
            return Directory.EnumerateFiles(
                path,
                pattern,
                SearchOption.TopDirectoryOnly)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path) ?? ""; }
        catch { return ""; }
    }
}

internal sealed class RecycleBinRecord
{
    public string FileName { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public DateTime? DeletedAtUtc { get; set; }
    public long OriginalSize { get; set; }
    public string InfoPath { get; set; } = "";
    public string RecycledDataPath { get; set; } = "";
    public bool RecycledDataPresent { get; set; }
    public long Version { get; set; }
}

internal sealed class VmEnvironmentRecord
{
    public bool IsVirtualMachine { get; set; }
    public string DetectedPlatform { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string Model { get; set; } = "";
    public string BiosManufacturer { get; set; } = "";
    public string BiosVersion { get; set; } = "";
}
