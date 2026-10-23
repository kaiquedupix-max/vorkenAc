using Vorken.Agent;

int assertions = 0;
void Check(bool condition, string message)
{
    assertions++;
    if (!condition) throw new Exception(message);
}
void Denied(Action action, string message)
{
    try { action(); }
    catch (UnauthorizedAccessException) { assertions++; return; }
    throw new Exception(message);
}

string root = Path.Combine(Path.GetTempPath(), "vorken-scope-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    foreach (string name in new[] { "Rust", "rUsTcLiEnT", "RustClient.exe", "RustDedicated", "EasyAntiCheat_EOS" })
        Check(InspectionScope.IsExcludedProcess(name), "Protected process was accepted: " + name);
    Check(!InspectionScope.IsExcludedProcess("steam"), "Unrelated process was excluded");
    Check(!InspectionScope.IsExcludedProcess("rust-analyzer"), "Unrelated Rust language tool was excluded");

    string normal = Path.Combine(root, "Downloads", "sample.txt");
    Directory.CreateDirectory(Path.GetDirectoryName(normal)!);
    File.WriteAllText(normal, "ordinary evidence");
    Check(ScanFile.ReadAllText(normal) == "ordinary evidence", "Ordinary evidence is unreadable");
    foreach (string relative in new[]
    {
        @"SteamLibrary\steamapps\common\CustomInstall\game.dll",
        @"Downloads\Rust\game.dll",
        @"AppData\LocalLow\Facepunch Studios\Rust\log.txt",
        @"Steam\userdata\123\252490\remote\config.cfg",
        @"Downloads\RustClient.exe",
        @"Downloads\RustClient_Data\data.bin",
        @"Program Files\EasyAntiCheat_EOS\service.exe",
        @"Downloads\RustDedicated_Data\data.bin"
    })
    {
        string path = Path.Combine(root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "protected");
        Check(!InspectionScope.CanInspectPath(path), "Protected path was accepted: " + path);
        Check(!ScanFile.Exists(path), "Protected file existence was exposed");
        Denied(() => ScanFile.ReadAllText(path), "Protected file was read");
        Denied(() => ScanFile.OpenRead(path).Dispose(), "Protected stream was opened");
        Check(!InspectionScope.CanInspectPath(path + ":Zone.Identifier"), "ADS bypassed exclusion");
    }
    Check(!InspectionScope.CanInspectPath(Path.Combine(root, @"STEAMA~1\common\x.dll")), "DOS short-name alias was accepted");
    string customInstall = Path.Combine(root, "CustomInstall");
    Check(!InspectionScope.CanInspectPath(Path.Combine(customInstall, "game.dll"), new[] { customInstall }), "Registered custom install bypassed exclusion");
    Check(InspectionScope.CanInspectPath(Path.Combine(root, "CustomInstallOther", "file.txt"), new[] { customInstall }), "Sibling prefix was incorrectly excluded");
    string[] listed = ScanDirectory.EnumerateFiles(root, "*", SearchOption.AllDirectories).ToArray();
    Check(listed.SequenceEqual(new[] { normal }), "Recursive scan entered protected storage");
    Check(!ScanDirectory.EnumerateDirectories(Path.Combine(root, "Downloads")).Any(p => Path.GetFileName(p) == "Rust"), "Protected folder was returned for traversal");
    Check(!ScanDirectory.EnumerateFiles(Path.Combine(root, "Downloads", "Rust")).Any(), "Explicit protected root was enumerated");
    Check(ScanDirectory.EnumerateFiles(root, "*.txt", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0 }).SequenceEqual(new[] { normal }), "USB recursive scan entered excluded paths");
    Check(!InspectionScope.CanInspectPath(Path.Combine(root, "Downloads", "x", "..", "Rust", "game.dll")), "Relative segments bypassed exclusion");
    Check(ScanDirectory.EnumerateFiles(Path.Combine(root, "Downloads"), "*.txt", SearchOption.TopDirectoryOnly).SequenceEqual(new[] { normal }), "Top-level pattern changed");

    // Junctions do not require symlink privileges and must not provide an alias into game storage.
    string alias = Path.Combine(root, "alias");
    using (var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe")
    {
        UseShellExecute = false,
        CreateNoWindow = true,
        ArgumentList = { "/d", "/c", "mklink", "/J", alias, Path.Combine(root, "Downloads", "Rust") },
        RedirectStandardOutput = true,
        RedirectStandardError = true
    })!)
    {
        process.WaitForExit();
        Check(process.ExitCode == 0, "Could not create junction fixture");
    }
    Check(!InspectionScope.CanInspectPath(Path.Combine(alias, "game.dll")), "Junction alias bypassed exclusion");
    Check(!ScanDirectory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Contains(Path.Combine(alias, "game.dll")), "Recursive scan followed junction");
    Directory.Delete(alias);
    Console.WriteLine($"PASS: {assertions} assertions. No game process was opened.");
}
finally
{
    Directory.Delete(root, true);
}
