using Vorken.Agent;
using System.Xml.Linq;
DateTime boot=DateTime.Parse("2026-10-23T10:00:00Z").ToUniversalTime(), captured=boot.AddHours(2);
int assertions=0;
void Check(bool condition,string message){assertions++;if(!condition)throw new Exception(message);}
string Event(string path,DateTime time,int id=4688,string channel="Security",string parent=""){
 XNamespace n="http://schemas.microsoft.com/win/2004/08/events/event";
 return new XElement(n+"Event",new XElement(n+"System",new XElement(n+"EventID",id),new XElement(n+"Channel",channel),new XElement(n+"TimeCreated",new XAttribute("SystemTime",time.ToString("O")))),new XElement(n+"EventData",new XElement(n+"Data",new XAttribute("Name",id==4688?"NewProcessName":"Image"),path),new XElement(n+"Data",new XAttribute("Name",id==4688?"ParentProcessName":"ParentImage"),parent))).ToString();
}
foreach(var path in new[]{@"C:\Rust\RustClient.exe",@"C:\Library\steamapps\common\Alternate\game.exe",@"C:\Other\Rust.exe",@"C:\Program Files\EasyAntiCheat_EOS\service.exe"})
 Check(ProcessJournalCollector.ParseEvent(Event(path,boot.AddHours(1)),boot,captured)==null,"Protected event retained");
var normal=ProcessJournalCollector.ParseEvent(Event(@"C:\Tools\app.exe",boot.AddHours(1),parent:@"C:\Rust\RustClient.exe"),boot,captured);
Check(normal!=null && normal.ParentProcessPath=="" && normal.ProcessName=="app.exe","Valid process or excluded parent failed");
Check(ProcessJournalCollector.ParseEvent(Event(@"C:\Tools\app.exe",boot.AddSeconds(-1)),boot,captured)==null,"Before boot retained");
Check(ProcessJournalCollector.ParseEvent(Event(@"C:\Tools\app.exe",captured.AddSeconds(1)),boot,captured)==null,"Future event retained");
Check(ProcessJournalCollector.ParseEvent(Event(@"C:\Tools\app.exe",boot.AddHours(1),1,"Microsoft-Windows-Sysmon/Operational"),boot,captured)?.Source=="Microsoft-Windows-Sysmon/Operational","Sysmon missing");
Check(ProcessJournalCollector.ParseEvent(Event(@"C:\Tools\app.exe",boot.AddHours(1),2,"Security"),boot,captured)==null,"Unrelated event retained");
Check(ProcessJournalCollector.ParseEvent("not xml",boot,captured)==null,"Malformed event retained");
foreach(var pair in new[]{(4689,"Security"),(5,"Microsoft-Windows-Sysmon/Operational")}) {
 string xml=Event(@"C:\Tools\app.exe",boot.AddHours(1),pair.Item1,pair.Item2);
 if(pair.Item1==4689) xml=xml.Replace("Name=\"Image\"","Name=\"ProcessName\"");
 var closed=ProcessJournalCollector.ParseEvent(xml,boot,captured);
 Check(closed?.EventId==pair.Item1 && closed.ProcessPath==@"C:\Tools\app.exe","Termination event missing");
}
Check(ProcessJournalCollector.ParseEvent(Event(@"C:\Tools\app.exe",boot.AddDays(-1)),DateTime.MinValue,captured)!=null,"Retained history before boot missing");
var metadata=new ProcessJournalReport();
Check(metadata.CollectionScope=="retained-history" && metadata.SystemDirectory==Environment.GetFolderPath(Environment.SpecialFolder.System),"Windows System32 identity missing");
Console.WriteLine($"PASS: {assertions} assertions; synthetic Windows events only, no game access.");
