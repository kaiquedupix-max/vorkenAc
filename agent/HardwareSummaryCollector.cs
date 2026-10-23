namespace Vorken.Agent;

internal static class HardwareSummaryCollector
{
    public static HardwareSummaryRecord Build(List<SerialDeviceRecord> devices)
    {
        var summary = new HardwareSummaryRecord
        {
            TotalRelevantDevices = devices.Count
        };

        foreach (SerialDeviceRecord device in devices)
        {
            string evidence = string.Join(
                " ",
                device.Name,
                device.DeviceId,
                device.PnpDeviceId,
                device.Manufacturer,
                device.PnpClass,
                device.Service)
                .ToLowerInvariant();

            bool arduino =
                evidence.Contains("arduino") ||
                evidence.Contains("vid_2341") ||
                evidence.Contains("vid_2a03");

            bool makcu =
                evidence.Contains("makcu") ||
                evidence.Contains("moku") ||
                evidence.Contains("vid_1a86&pid_55d3") ||
                evidence.Contains("vid_303a&pid_0009") ||
                evidence.Contains("vid_303a&pid_1001");

            bool ch34x =
                evidence.Contains("ch340") ||
                evidence.Contains("ch341") ||
                evidence.Contains("ch343") ||
                evidence.Contains("vid_1a86");

            bool cp210x =
                evidence.Contains("cp210") ||
                evidence.Contains("vid_10c4");

            bool ftdi =
                evidence.Contains("ftdi") ||
                evidence.Contains("vid_0403");

            if (arduino) summary.ArduinoCount++;
            if (makcu) summary.MakcuCount++;
            if (ch34x) summary.Ch34xCount++;
            if (cp210x) summary.Cp210xCount++;
            if (ftdi) summary.FtdiCount++;

            if (!arduino && !makcu && !ch34x && !cp210x && !ftdi)
                summary.OtherSerialCount++;
        }

        return summary;
    }
}

internal sealed class HardwareSummaryRecord
{
    public int TotalRelevantDevices { get; set; }
    public int ArduinoCount { get; set; }
    public int MakcuCount { get; set; }
    public int Ch34xCount { get; set; }
    public int Cp210xCount { get; set; }
    public int FtdiCount { get; set; }
    public int OtherSerialCount { get; set; }
}
