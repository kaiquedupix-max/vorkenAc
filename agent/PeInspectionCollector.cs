using System.Buffers.Binary;
using System.Text;

namespace Vorken.Agent;

internal static class PeInspectionCollector
{
    private static readonly string[] PackerTokens =
    {
        "UPX0", "UPX1", "UPX!", "VMProtect", ".vmp0", ".vmp1",
        "Themida", "WinLicense", "Enigma Protector", "MPRESS",
        "ASPack", "PECompact", "Obsidium"
    };

    private static readonly string[] SuspiciousApiTokens =
    {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "SetWindowsHookEx",
        "QueueUserAPC",
        "MapViewOfFile",
        "MiniDumpWriteDump",
        "WinVerifyTrust",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent"
    };

    private static readonly string[] EnvironmentProbeTokens =
    {
        "VMware",
        "VirtualBox",
        "VBox",
        "QEMU",
        "Sandboxie",
        "Wireshark",
        "ProcessHacker",
        "x64dbg",
        "ollydbg"
    };

    public static List<PeInspectionRecord> Collect(List<FileRecord> files)
    {
        var result = new List<PeInspectionRecord>();

        foreach (FileRecord file in files)
        {
            if (result.Count >= 1200)
                break;

            string extension = (file.Extension ?? "").ToLowerInvariant();

            if (extension is not ".exe" and not ".dll" and not ".sys" and not ".scr" and not ".com")
                continue;

            if (string.IsNullOrWhiteSpace(file.Path) || !File.Exists(file.Path))
                continue;

            try
            {
                FileInfo info = new(file.Path);
                if (info.Length <= 0 || info.Length > 350L * 1024L * 1024L)
                    continue;

                byte[] sample = ReadSample(file.Path, 8 * 1024 * 1024);
                if (sample.Length < 64)
                    continue;

                double entropy = ShannonEntropy(sample);
                List<string> sectionNames = TryReadPeSectionNames(sample);

                string ascii = ToSearchableAscii(sample);

                List<string> packerMatches = MatchTokens(ascii, PackerTokens);
                List<string> apiMatches = MatchTokens(ascii, SuspiciousApiTokens);
                List<string> environmentMatches = MatchTokens(ascii, EnvironmentProbeTokens);

                bool highEntropy =
                    entropy >= 7.35 &&
                    info.Length >= 64 * 1024;

                bool packedLike =
                    packerMatches.Count > 0 ||
                    (
                        highEntropy &&
                        file.Signed != true &&
                        sectionNames.Any(x =>
                            x.StartsWith(".vmp", StringComparison.OrdinalIgnoreCase) ||
                            x.StartsWith("UPX", StringComparison.OrdinalIgnoreCase))
                    );

                if (
                    !highEntropy &&
                    packerMatches.Count == 0 &&
                    apiMatches.Count == 0 &&
                    environmentMatches.Count == 0 &&
                    file.RandomLikeName != true)
                {
                    continue;
                }

                result.Add(new PeInspectionRecord
                {
                    Name = file.Name,
                    Path = file.Path,
                    Sha256 = file.Sha256 ?? "",
                    Signed = file.Signed,
                    SignerSubject = file.SignerSubject ?? "",
                    Size = info.Length,
                    Entropy = Math.Round(entropy, 3),
                    HighEntropy = highEntropy,
                    PackedLike = packedLike,
                    PackerIndicators = packerMatches,
                    SuspiciousApis = apiMatches,
                    EnvironmentProbeIndicators = environmentMatches,
                    SectionNames = sectionNames,
                    CompilationTimeUtc = file.CompilationTimeUtc,
                    RandomLikeName = file.RandomLikeName
                });
            }
            catch
            {
            }
        }

        return result;
    }

    private static byte[] ReadSample(string path, int maxBytes)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);

        int length = (int)Math.Min(stream.Length, maxBytes);
        byte[] buffer = new byte[length];

        int offset = 0;
        while (offset < length)
        {
            int read = stream.Read(buffer, offset, length - offset);
            if (read <= 0) break;
            offset += read;
        }

        if (offset == length)
            return buffer;

        return buffer[..offset];
    }

    private static double ShannonEntropy(byte[] data)
    {
        if (data.Length == 0)
            return 0;

        Span<int> counts = stackalloc int[256];

        foreach (byte value in data)
            counts[value]++;

        double entropy = 0;

        for (int i = 0; i < counts.Length; i++)
        {
            if (counts[i] == 0) continue;

            double p = (double)counts[i] / data.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static string ToSearchableAscii(byte[] data)
    {
        var builder = new StringBuilder(data.Length);

        foreach (byte value in data)
        {
            builder.Append(
                value >= 0x20 && value <= 0x7E
                    ? (char)value
                    : ' ');
        }

        return builder.ToString();
    }

    private static List<string> MatchTokens(
        string haystack,
        IEnumerable<string> tokens)
    {
        return tokens
            .Where(token =>
                haystack.Contains(
                    token,
                    StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(40)
            .ToList();
    }

    private static List<string> TryReadPeSectionNames(byte[] bytes)
    {
        var result = new List<string>();

        try
        {
            if (bytes.Length < 0x100 ||
                bytes[0] != (byte)'M' ||
                bytes[1] != (byte)'Z')
            {
                return result;
            }

            int peOffset = BinaryPrimitives.ReadInt32LittleEndian(
                bytes.AsSpan(0x3C, 4));

            if (peOffset < 0 ||
                peOffset + 24 >= bytes.Length)
            {
                return result;
            }

            if (
                bytes[peOffset] != (byte)'P' ||
                bytes[peOffset + 1] != (byte)'E' ||
                bytes[peOffset + 2] != 0 ||
                bytes[peOffset + 3] != 0)
            {
                return result;
            }

            ushort sections =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    bytes.AsSpan(peOffset + 6, 2));

            ushort optionalHeaderSize =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    bytes.AsSpan(peOffset + 20, 2));

            int sectionOffset =
                peOffset + 24 + optionalHeaderSize;

            for (int i = 0; i < Math.Min(sections, (ushort)32); i++)
            {
                int offset = sectionOffset + i * 40;
                if (offset + 8 > bytes.Length)
                    break;

                string name = Encoding.ASCII
                    .GetString(bytes, offset, 8)
                    .TrimEnd('\0', ' ');

                if (!string.IsNullOrWhiteSpace(name))
                    result.Add(name);
            }
        }
        catch
        {
        }

        return result;
    }
}

internal sealed class PeInspectionRecord
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public bool Signed { get; set; }
    public string SignerSubject { get; set; } = "";
    public long Size { get; set; }
    public double Entropy { get; set; }
    public bool HighEntropy { get; set; }
    public bool PackedLike { get; set; }
    public List<string> PackerIndicators { get; set; } = new();
    public List<string> SuspiciousApis { get; set; } = new();
    public List<string> EnvironmentProbeIndicators { get; set; } = new();
    public List<string> SectionNames { get; set; } = new();
    public DateTime? CompilationTimeUtc { get; set; }
    public bool RandomLikeName { get; set; }
}
