using System.Management;

namespace Vorken.Agent;

internal static class SecurityProductCollector
{
    public static List<SecurityProductRecord> Collect()
    {
        var result = new List<SecurityProductRecord>();

        CollectNamespace(
            @"root\SecurityCenter2",
            "AntiVirusProduct",
            "Antivirus",
            result);

        CollectNamespace(
            @"root\SecurityCenter2",
            "FirewallProduct",
            "Firewall",
            result);

        CollectNamespace(
            @"root\SecurityCenter2",
            "AntiSpywareProduct",
            "AntiSpyware",
            result);

        return result
            .GroupBy(
                x => $"{x.Category}|{x.DisplayName}|{x.InstanceGuid}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(250)
            .ToList();
    }

    private static void CollectNamespace(
        string scopePath,
        string className,
        string category,
        List<SecurityProductRecord> result)
    {
        try
        {
            var scope = new ManagementScope(scopePath);
            scope.Connect();

            using var searcher =
                new ManagementObjectSearcher(
                    scope,
                    new ObjectQuery(
                        $"SELECT * FROM {className}"));

            foreach (ManagementObject item in searcher.Get())
            {
                result.Add(new SecurityProductRecord
                {
                    Category = category,
                    DisplayName =
                        Convert.ToString(item["displayName"]) ?? "",
                    InstanceGuid =
                        Convert.ToString(item["instanceGuid"]) ?? "",
                    PathToSignedProductExe =
                        Convert.ToString(item["pathToSignedProductExe"]) ?? "",
                    PathToSignedReportingExe =
                        Convert.ToString(item["pathToSignedReportingExe"]) ?? "",
                    ProductState =
                        Convert.ToString(item["productState"]) ?? "",
                    Timestamp =
                        Convert.ToString(item["timestamp"]) ?? ""
                });
            }
        }
        catch
        {
        }
    }
}

internal sealed class SecurityProductRecord
{
    public string Category { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string InstanceGuid { get; set; } = "";
    public string PathToSignedProductExe { get; set; } = "";
    public string PathToSignedReportingExe { get; set; } = "";
    public string ProductState { get; set; } = "";
    public string Timestamp { get; set; } = "";
}
