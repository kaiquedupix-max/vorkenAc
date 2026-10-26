namespace Vorken.Agent;

internal sealed class ProcessCreationRecord
{
    public DateTime TimeCreatedUtc { get; set; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    public string ParentProcessName { get; set; } = "";
    public string ParentProcessPath { get; set; } = "";
    public bool ProcessPresent { get; set; }
    public string DriveType { get; set; } = "";
    public string ProcessId { get; set; } = "";
    public string ProcessGuid { get; set; } = "";
    public string Source { get; set; } = "Security";
    public int EventId { get; set; } = 4688;
    public bool Signed { get; set; }
    public string SignerSubject { get; set; } = "";
}

