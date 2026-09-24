using Microsoft.Win32;
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Forms;

namespace Vorken.Agent;

internal static class Program
{
    private const string AgentVersion = "1.0.3";
    private const string DefaultServerUrl = "https://vorkenac.guerrafriarust.com.br";

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

    private static Action<string>? _statusSink;

    [STAThread]
    public static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new AgentMainForm(args));
    }

    internal static async Task<int> RunAnalysisAsync(
        string[] args,
        Action<string>? status = null)
    {
        _statusSink = status;
        ReportStatus("Preparando a análise...");

        try
        {
            AgentConfig config = LoadConfig(args);
            ReportStatus("Conectando ao servidor do Vorken...");

            using var http = new HttpClient
            {
                BaseAddress = new Uri(config.ServerUrl.TrimEnd('/') + "/"),
                Timeout = TimeSpan.FromSeconds(120)
            };

            RulesResponse rulesPayload =
                await LoadRulesAsync(http, config.Token);

            ReportStatus("Configuração recebida. Iniciando coleta segura...");
            var rules = rulesPayload.Rules;

            string machineFingerprint =
                EchoEnvironmentCollector.ComputeMachineFingerprint();

            await PostJsonAsync(
                http,
                $"api/agent/{Uri.EscapeDataString(config.Token)}/start",
                new
                {
                    machineName = Environment.MachineName,
                    osVersion = Environment.OSVersion.VersionString,
                    agentVersion = AgentVersion,
                    machineFingerprint
                });

            ReportStatus("Coletando evidências técnicas do computador...");

            var errors = new List<string>();

            List<UsbDeviceRecord> usbCurrent = SafeCollect(
                "USB atual",
                CollectCurrentUsbDevices,
                errors);

            List<UsbHistoryRecord> usbHistory = SafeCollect(
                "Histórico USB",
                () => CollectUsbHistory(usbCurrent),
                errors);

            List<UsbDeviceEventRecord> usbTimeline = SafeCollect(
                "Linha do tempo USB",
                UsbEventCollector.Collect,
                errors);

            try
            {
                UsbEventCollector.EnrichUsbHistory(usbHistory, usbTimeline);
                Console.WriteLine("  ✓ Horários USB correlacionados");
            }
            catch (Exception ex)
            {
                errors.Add("Correlação USB: " + ex.Message);
                Console.WriteLine("  ! Correlação USB: indisponível");
            }

            List<SerialDeviceRecord> serialDevices = SafeCollect(
                "Dispositivos seriais",
                CollectSerialDevices,
                errors);

            HardwareSummaryRecord hardwareSummary =
                HardwareSummaryCollector.Build(serialDevices);

            Console.WriteLine(
                $"  ✓ Placas: {hardwareSummary.TotalRelevantDevices} | " +
                $"Arduino: {hardwareSummary.ArduinoCount} | " +
                $"MAKCU/Moku: {hardwareSummary.MakcuCount}");

            List<PrefetchRecord> prefetch = SafeCollect(
                "Prefetch básico",
                CollectPrefetch,
                errors);

            List<PrefetchExecutionRecord> prefetchExecutions = SafeCollect(
                "Prefetch detalhado",
                PrefetchExecutionCollector.Collect,
                errors);

            List<FileRecord> files = SafeCollect(
                "Arquivos",
                () => CollectCandidateFiles(prefetch, rules),
                errors);

            List<PeInspectionRecord> peInspections = SafeCollect(
                "Análise PE / entropia / packers",
                () => PeInspectionCollector.Collect(files),
                errors);

            List<ZoneIdentifierRecord> zoneIdentifiers = SafeCollect(
                "Zone.Identifier / origem de downloads",
                ZoneIdentifierCollector.Collect,
                errors);

            List<AlternateDataStreamRecord> alternateDataStreams = SafeCollect(
                "Alternate Data Streams",
                () => AlternateDataStreamCollector.Collect(files),
                errors);

            List<AutorunIntegrityRecord> autorunIntegrity = SafeCollect(
                "Autoruns e tarefas agendadas",
                AutorunIntegrityCollector.Collect,
                errors);

            List<ProcessRecord> processes = SafeCollect(
                "Processos",
                CollectProcesses,
                errors);

            List<ProcessModuleIntegrityRecord> processModuleIntegrity = SafeCollect(
                "Módulos em processos críticos",
                ProcessModuleIntegrityCollector.Collect,
                errors);

            List<ProcessMemoryIntegrityRecord> processMemoryIntegrity = SafeCollect(
                "Memória executável privada / manual-map",
                ProcessMemoryIntegrityCollector.Collect,
                errors);

            List<WindowProtectionRecord> protectedWindows = SafeCollect(
                "Janelas excluídas de captura",
                WindowProtectionCollector.Collect,
                errors);

            List<ServiceRecord> services = SafeCollect(
                "Serviços",
                CollectServices,
                errors);

            List<DriverRecord> drivers = SafeCollect(
                "Drivers",
                CollectDrivers,
                errors);

            List<StartupRecord> startup = SafeCollect(
                "Inicialização",
                CollectStartupEntries,
                errors);

            List<BamRecord> bam = SafeCollect(
                "BAM/DAM",
                AdvancedCollectors.CollectBam,
                errors);

            List<UserAssistRecord> userAssist = SafeCollect(
                "UserAssist",
                AdvancedCollectors.CollectUserAssist,
                errors);

            List<MuiCacheRecord> muiCache = SafeCollect(
                "MUICache",
                AdvancedCollectors.CollectMuiCache,
                errors);

            List<PcaRecord> pca = SafeCollect(
                "PCA Store",
                AdvancedCollectors.CollectPcaStore,
                errors);

            List<AmcacheExecutionRecord> amcache = SafeCollect(
                "Amcache",
                AmcacheExecutionCollector.Collect,
                errors);

            List<ShimCacheRecord> shimCache = SafeCollect(
                "ShimCache",
                ShimCacheExecutionCollector.Collect,
                errors);

            List<SetupApiUsbRecord> setupApiUsb = SafeCollect(
                "SetupAPI USB",
                AdvancedCollectors.CollectSetupApiUsb,
                errors);

            List<PowerShellRuleHit> powerShellHits = SafeCollect(
                "PowerShell por regra",
                () => AdvancedCollectors.CollectPowerShellRuleHits(rules),
                errors);

            List<PowerShellArtifactRecord> powerShellArtifacts = SafeCollect(
                "PowerShell histórico / eventos",
                PowerShellForensicsCollector.Collect,
                errors);

            List<PrefetchIntegrityRecord> prefetchIntegrity = SafeCollect(
                "Integridade do Prefetch",
                AdvancedCollectors.CollectPrefetchIntegrity,
                errors);

            List<VolumeRecord> hiddenVolumes = SafeCollect(
                "Volumes sem letra",
                AdvancedCollectors.CollectVolumesWithoutDriveLetter,
                errors);

            List<EventLogSignalRecord> logClearSignals = SafeCollect(
                "Sinais de limpeza de logs",
                AdvancedCollectors.CollectRecentLogClearSignals,
                errors);

            List<ProcessCreationRecord> processCreationEvents = SafeCollect(
                "Event Log 4688",
                DeepForensicCollector.CollectProcessCreationEvents,
                errors);

            List<DefenderDetectionRecord> defenderDetections = SafeCollect(
                "Histórico do Microsoft Defender",
                DeepForensicCollector.CollectDefenderDetections,
                errors);

            List<RecentShortcutRecord> recentShortcuts = SafeCollect(
                "Atalhos recentes",
                DeepForensicCollector.CollectRecentShortcuts,
                errors);

            List<CrashArtifactRecord> crashArtifacts = SafeCollect(
                "Windows Error Reporting / crashes",
                CrashArtifactCollector.Collect,
                errors);

            List<SecurityProductRecord> securityProducts = SafeCollect(
                "Produtos de segurança registrados",
                SecurityProductCollector.Collect,
                errors);

            List<RecycleBinRecord> recycleBin = SafeCollect(
                "Lixeira do Windows",
                EchoEnvironmentCollector.CollectRecycleBin,
                errors);

            VmEnvironmentRecord vmEnvironment;
            try
            {
                vmEnvironment = EchoEnvironmentCollector.CollectVmEnvironment();
                Console.WriteLine(
                    vmEnvironment.IsVirtualMachine
                        ? $"  ✓ Ambiente virtual: {vmEnvironment.DetectedPlatform}"
                        : "  ✓ Ambiente virtual: não detectado");
            }
            catch (Exception ex)
            {
                errors.Add("Ambiente virtual: " + ex.Message);
                vmEnvironment = new VmEnvironmentRecord();
                Console.WriteLine("  ! Ambiente virtual: indisponível");
            }

            List<BrowserDownloadRecord> browserDownloads = SafeCollect(
                "Histórico de downloads",
                BrowserDownloadsCollector.Collect,
                errors);

            List<BrowserHistoryRecord> browserHistorySignals = SafeCollect(
                "Histórico suspeito de navegação",
                () => BrowserHistoryCollector.CollectSuspicious(
                    rulesPayload.ThreatCatalog),
                errors);

            List<RecoveredBrowserArtifact> browserRecoveredArtifacts = SafeCollect(
                "Vestígios de histórico apagado",
                () => BrowserArtifactRecoveryCollector.Collect(
                    rulesPayload.ThreatCatalog),
                errors);

            List<NetworkIndicatorRecord> networkIndicators = SafeCollect(
                "Rede / DNS / conexões TCP",
                () => NetworkIndicatorCollector.Collect(
                    rulesPayload.ThreatCatalog),
                errors);

            List<DeletedUsnRecord> deletedUsnRecords = SafeCollect(
                "Arquivos apagados no USN Journal",
                UsnDeletionCollector.Collect,
                errors);

            List<ExtensionMismatchRecord> extensionMismatches = SafeCollect(
                "Extensões modificadas",
                DeepForensicCollector.CollectModifiedExtensions,
                errors);

            List<DefenderExclusionRecord> defenderExclusions = SafeCollect(
                "Exclusões do Defender",
                DeepForensicCollector.CollectDefenderExclusions,
                errors);

            List<BootIntegrityRecord> bootIntegrity = SafeCollect(
                "Integridade de boot",
                DeepForensicCollector.CollectBootIntegrityFlags,
                errors);

            List<SystemTimeChangeRecord> systemTimeChanges = SafeCollect(
                "Alterações de horário",
                DeepForensicCollector.CollectSystemTimeChanges,
                errors);

            List<VirtualDiskRecord> virtualDisks = SafeCollect(
                "Discos virtuais",
                DeepForensicCollector.CollectVirtualDiskIndicators,
                errors);

            List<RustModuleRecord> rustModules = SafeCollect(
                "Módulos do Rust",
                DeepForensicCollector.CollectRustModules,
                errors);

            List<UsnJournalStateRecord> usnJournalState = SafeCollect(
                "Estado do USN Journal",
                DeepForensicCollector.CollectUsnJournalState,
                errors);

            List<UsnActivityRecord> usnActivity = SafeCollect(
                "JournalTrace / atividade USN",
                UsnActivityCollector.Collect,
                errors);

            List<SystemIntegrityExpansionRecord> systemIntegrityExpansion = SafeCollect(
                "Integridade ampliada do Windows",
                SystemIntegrityExpansionCollector.Collect,
                errors);

            ActivityHistoryState activityHistory;
            try
            {
                activityHistory = DeepForensicCollector.CollectActivityHistoryState();
                Console.WriteLine("  ✓ Activity History");
            }
            catch (Exception ex)
            {
                errors.Add("Activity History: " + ex.Message);
                activityHistory = new ActivityHistoryState();
                Console.WriteLine("  ! Activity History: indisponível");
            }

            SystemArtifactRecord systemArtifacts;
            try
            {
                systemArtifacts = AdvancedCollectors.CollectSystemArtifactState();
                Console.WriteLine("  ✓ Estado dos artefatos do Windows");
            }
            catch (Exception ex)
            {
                errors.Add("Estado dos artefatos: " + ex.Message);
                systemArtifacts = new SystemArtifactRecord();
                Console.WriteLine("  ! Estado dos artefatos: indisponível");
            }

            var report = new ScanReport
            {
                AgentVersion = AgentVersion,
                CollectedAtUtc = DateTime.UtcNow,
                Machine = new MachineRecord
                {
                    MachineName = Environment.MachineName,
                    OsVersion = Environment.OSVersion.VersionString,
                    Is64BitOs = Environment.Is64BitOperatingSystem,
                    Fingerprint = machineFingerprint
                },
                UsbCurrent = usbCurrent,
                UsbHistory = usbHistory,
                UsbTimeline = usbTimeline,
                SerialDevices = serialDevices,
                HardwareSummary = hardwareSummary,
                Processes = processes,
                Prefetch = prefetch,
                PrefetchExecutions = prefetchExecutions,
                Services = services,
                Drivers = drivers,
                Startup = startup,
                Files = files,
                PeInspections = peInspections,
                ZoneIdentifiers = zoneIdentifiers,
                AlternateDataStreams = alternateDataStreams,
                AutorunIntegrity = autorunIntegrity,
                ProcessModuleIntegrity = processModuleIntegrity,
                ProcessMemoryIntegrity = processMemoryIntegrity,
                ProtectedWindows = protectedWindows,
                Bam = bam,
                UserAssist = userAssist,
                MuiCache = muiCache,
                Pca = pca,
                Amcache = amcache,
                ShimCache = shimCache,
                SetupApiUsb = setupApiUsb,
                PowerShellHits = powerShellHits,
                PowerShellArtifacts = powerShellArtifacts,
                PrefetchIntegrity = prefetchIntegrity,
                HiddenVolumes = hiddenVolumes,
                LogClearSignals = logClearSignals,
                ProcessCreationEvents = processCreationEvents,
                DefenderDetections = defenderDetections,
                RecentShortcuts = recentShortcuts,
                CrashArtifacts = crashArtifacts,
                SecurityProducts = securityProducts,
                RecycleBin = recycleBin,
                VmEnvironment = vmEnvironment,
                BrowserDownloads = browserDownloads,
                BrowserHistorySignals = browserHistorySignals,
                BrowserRecoveredArtifacts = browserRecoveredArtifacts,
                NetworkIndicators = networkIndicators,
                DeletedUsnRecords = deletedUsnRecords,
                ExtensionMismatches = extensionMismatches,
                DefenderExclusions = defenderExclusions,
                BootIntegrity = bootIntegrity,
                ActivityHistory = activityHistory,
                SystemTimeChanges = systemTimeChanges,
                VirtualDisks = virtualDisks,
                RustModules = rustModules,
                UsnJournalState = usnJournalState,
                UsnActivity = usnActivity,
                SystemIntegrityExpansion = systemIntegrityExpansion,
                SystemArtifacts = systemArtifacts,
                Errors = errors
            };

            ReportStatus("Preparando o relatório completo para envio...");

            string reportRoute =
                $"api/agent/{Uri.EscapeDataString(config.Token)}/report";

            HttpResponseMessage response =
                await SendCompressedReportAsync(
                    http,
                    reportRoute,
                    report);

            if (!response.IsSuccessStatusCode &&
                IsRetryableUploadStatus(response.StatusCode))
            {
                ReportStatus(
                    $"Servidor respondeu {(int)response.StatusCode}. Tentando reenviar o relatório completo...");

                response.Dispose();

                await Task.Delay(TimeSpan.FromSeconds(2));

                response =
                    await SendCompressedReportAsync(
                        http,
                        reportRoute,
                        report);
            }

            using (response)
            {
                if (!response.IsSuccessStatusCode)
                {
                    string body = await response.Content.ReadAsStringAsync();

                    ReportStatus(
                        $"Falha ao enviar os dados: {(int)response.StatusCode}");

                    if (!string.IsNullOrWhiteSpace(body))
                    {
                        ReportStatus(
                            "Resposta do servidor: " +
                            body.Trim().Replace("\r", " ").Replace("\n", " "));
                    }

                    return 3;
                }
            }

            ReportStatus("Dados enviados para análise com sucesso.");
            return 0;
        }
        catch (Exception ex)
        {
            ReportStatus("Falha no Vorken: " + ex.Message);
            return 1;
        }
    }

    private static void ReportStatus(string message)
    {
        try
        {
            _statusSink?.Invoke(message);
        }
        catch
        {
        }
    }

    private static void PrintBanner()
    {
        Console.Clear();
        Console.BackgroundColor = ConsoleColor.Black;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("║                                                      ║");
        Console.WriteLine("║              V O R K E N   A N T I C H E A T         ║");
        Console.WriteLine("║                                                      ║");
        Console.WriteLine($"║                    AGENT v{AgentVersion,-8}                 ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  Defensive forensic scanner · consent-based inspection");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void WriteInfo(string value)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("  i ");
        Console.ResetColor();
        Console.WriteLine(value);
    }

    private static void WriteSuccess(string value)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write("  ✓ ");
        Console.ResetColor();
        Console.WriteLine(value);
    }

    private static void WriteWarning(string value)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("  ! ");
        Console.ResetColor();
        Console.WriteLine(value);
    }

    private static void WriteError(string value)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("  ✕ ");
        Console.ResetColor();
        Console.WriteLine(value);
    }

    private static void WriteDim(string value)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(value);
        Console.ResetColor();
    }

    private static AgentConfig LoadConfig(string[] args)
    {
        string? token = null;
        string? server = null;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--token", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                token = args[++i];
            }
            else if (args[i].Equals("--server", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                server = args[++i];
            }
        }

        string configPath = Path.Combine(AppContext.BaseDirectory, "vorken-analysis.json");

        if (File.Exists(configPath))
        {
            AgentConfig? fileConfig =
                JsonSerializer.Deserialize<AgentConfig>(
                    File.ReadAllText(configPath),
                    JsonOptions);

            token ??= fileConfig?.Token;
            server ??= fileConfig?.ServerUrl;
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            string executableName =
                Path.GetFileName(
                    Environment.ProcessPath ??
                    AppContext.BaseDirectory);

            var match =
                System.Text.RegularExpressions.Regex.Match(
                    executableName,
                    @"--(?<token>[A-Za-z0-9_-]{20,80})(?: \(\d+\))?\.exe$",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            if (match.Success)
            {
                token = match.Groups["token"].Value;
                server ??= DefaultServerUrl;
            }
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            throw new InvalidOperationException(
                "Token da análise ausente. Baixe novamente o Vorken pelo link da análise.");
        }

        server ??= DefaultServerUrl;

        return new AgentConfig
        {
            Token = token.Trim(),
            ServerUrl = server.Trim()
        };
    }

    private static async Task<RulesResponse> LoadRulesAsync(HttpClient http, string token)
    {
        using HttpResponseMessage response =
            await http.GetAsync($"api/agent/{Uri.EscapeDataString(token)}/rules");

        response.EnsureSuccessStatusCode();

        RulesResponse? payload =
            await response.Content.ReadFromJsonAsync<RulesResponse>(JsonOptions);

        return payload ?? new RulesResponse();
    }

    private static async Task PostJsonAsync(HttpClient http, string route, object body)
    {
        using HttpResponseMessage response =
            await http.PostAsJsonAsync(route, body, JsonOptions);

        response.EnsureSuccessStatusCode();
    }

    private static bool IsRetryableUploadStatus(HttpStatusCode statusCode)
    {
        int code = (int)statusCode;

        return code is
            408 or
            413 or
            429 or
            500 or
            502 or
            503 or
            504;
    }

    private static async Task<HttpResponseMessage> SendCompressedReportAsync(
        HttpClient http,
        string route,
        ScanReport report)
    {
        byte[] json =
            JsonSerializer.SerializeToUtf8Bytes(
                report,
                JsonOptions);

        byte[] compressed;

        using (
            var output =
                new MemoryStream())
        {
            using (
                var gzip =
                    new GZipStream(
                        output,
                        CompressionLevel.Fastest,
                        leaveOpen: true))
            {
                await gzip.WriteAsync(json);
            }

            compressed =
                output.ToArray();
        }

        double sourceMb =
            json.Length / 1024d / 1024d;

        double compressedMb =
            compressed.Length / 1024d / 1024d;

        ReportStatus(
            $"Enviando relatório: {sourceMb:F1} MB -> {compressedMb:F1} MB compactado.");

        var request =
            new HttpRequestMessage(
                HttpMethod.Post,
                route);

        var content =
            new ByteArrayContent(
                compressed);

        content.Headers.ContentType =
            new MediaTypeHeaderValue(
                "application/json");

        content.Headers.ContentEncoding.Add(
            "gzip");

        request.Content = content;

        try
        {
            return await http.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead);
        }
        finally
        {
            request.Dispose();
        }
    }

    private static List<T> SafeCollect<T>(
        string moduleName,
        Func<List<T>> collector,
        List<string> errors)
    {
        try
        {
            List<T> result = collector();
            ReportStatus($"✓ {moduleName}: {result.Count}");
            return result;
        }
        catch (Exception ex)
        {
            errors.Add($"{moduleName}: {ex.Message}");
            ReportStatus($"! {moduleName}: indisponível");
            return new List<T>();
        }
    }

    private static List<UsbDeviceRecord> CollectCurrentUsbDevices()
    {
        var result = new List<UsbDeviceRecord>();

        using var searcher =
            new ManagementObjectSearcher(
                "SELECT Name,DeviceID,PNPDeviceID,Manufacturer,Status FROM Win32_PnPEntity");

        foreach (ManagementObject item in searcher.Get())
        {
            string pnp = Convert.ToString(item["PNPDeviceID"]) ?? "";
            string deviceId = Convert.ToString(item["DeviceID"]) ?? "";

            if (!pnp.StartsWith("USB", StringComparison.OrdinalIgnoreCase) &&
                !deviceId.StartsWith("USB", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            result.Add(new UsbDeviceRecord
            {
                Name = Convert.ToString(item["Name"]) ?? "",
                DeviceId = deviceId,
                PnpDeviceId = pnp,
                Manufacturer = Convert.ToString(item["Manufacturer"]) ?? "",
                Status = Convert.ToString(item["Status"]) ?? "",
                Present = true
            });
        }

        return result
            .GroupBy(x => x.PnpDeviceId + "|" + x.DeviceId, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .ToList();
    }

    private static List<UsbHistoryRecord> CollectUsbHistory(List<UsbDeviceRecord> current)
    {
        var result = new List<UsbHistoryRecord>();
        using RegistryKey? root =
            Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");

        if (root == null) return result;

        HashSet<string> currentText =
            current
                .SelectMany(x => new[] { x.DeviceId, x.PnpDeviceId, x.Name })
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.ToLowerInvariant())
                .ToHashSet();

        foreach (string deviceClass in root.GetSubKeyNames())
        {
            using RegistryKey? classKey = root.OpenSubKey(deviceClass);
            if (classKey == null) continue;

            foreach (string instance in classKey.GetSubKeyNames())
            {
                using RegistryKey? instanceKey = classKey.OpenSubKey(instance);
                if (instanceKey == null) continue;

                string friendlyName =
                    Convert.ToString(instanceKey.GetValue("FriendlyName")) ?? "";

                string deviceDesc =
                    Convert.ToString(instanceKey.GetValue("DeviceDesc")) ?? "";

                string manufacturer =
                    Convert.ToString(instanceKey.GetValue("Mfg")) ?? "";

                bool present =
                    currentText.Any(x =>
                        x.Contains(instance.ToLowerInvariant()) ||
                        (!string.IsNullOrWhiteSpace(friendlyName) &&
                         x.Contains(friendlyName.ToLowerInvariant())));

                result.Add(new UsbHistoryRecord
                {
                    DeviceClass = deviceClass,
                    InstanceId = instance,
                    FriendlyName = friendlyName,
                    DeviceDescription = deviceDesc,
                    Manufacturer = manufacturer,
                    Present = present
                });
            }
        }

        return result;
    }

    private static List<SerialDeviceRecord> CollectSerialDevices()
    {
        string[] keywords =
        {
            "arduino",
            "makcu",
            "moku",
            "ch340",
            "ch341",
            "ch343",
            "cp210",
            "ftdi",
            "usb serial",
            "usb-serial",
            "serial port",
            "vid_2341",
            "vid_2a03",
            "vid_1a86",
            "vid_10c4",
            "vid_0403",
            "vid_303a"
        };

        var result = new List<SerialDeviceRecord>();

        using var searcher =
            new ManagementObjectSearcher(
                "SELECT Name,DeviceID,PNPDeviceID,Manufacturer,Status,PNPClass,Service FROM Win32_PnPEntity");

        foreach (ManagementObject item in searcher.Get())
        {
            string name = Convert.ToString(item["Name"]) ?? "";
            string deviceId = Convert.ToString(item["DeviceID"]) ?? "";
            string pnpDeviceId = Convert.ToString(item["PNPDeviceID"]) ?? "";
            string manufacturer = Convert.ToString(item["Manufacturer"]) ?? "";
            string pnpClass = Convert.ToString(item["PNPClass"]) ?? "";
            string service = Convert.ToString(item["Service"]) ?? "";

            string combined =
                string.Join(
                    " ",
                    name,
                    deviceId,
                    pnpDeviceId,
                    manufacturer,
                    pnpClass,
                    service)
                .ToLowerInvariant();

            bool comPortName =
                System.Text.RegularExpressions.Regex.IsMatch(
                    name,
                    @"\(COM\d+\)",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            bool serialClass =
                pnpClass.Equals("Ports", StringComparison.OrdinalIgnoreCase);

            if (!keywords.Any(combined.Contains) && !comPortName && !serialClass)
                continue;

            result.Add(new SerialDeviceRecord
            {
                Name = name,
                DeviceId = deviceId,
                PnpDeviceId = pnpDeviceId,
                Manufacturer = manufacturer,
                Status = Convert.ToString(item["Status"]) ?? "",
                PnpClass = pnpClass,
                Service = service
            });
        }

        return result
            .GroupBy(
                x => x.PnpDeviceId + "|" + x.DeviceId,
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .ToList();
    }

    private static List<PrefetchRecord> CollectPrefetch()
    {
        string directory =
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "Prefetch");

        var result = new List<PrefetchRecord>();

        if (!Directory.Exists(directory)) return result;

        foreach (string file in Directory.EnumerateFiles(directory, "*.pf", SearchOption.TopDirectoryOnly))
        {
            try
            {
                var info = new FileInfo(file);
                result.Add(new PrefetchRecord
                {
                    Name = info.Name,
                    Path = info.FullName,
                    LastWriteUtc = info.LastWriteTimeUtc,
                    Size = info.Length
                });
            }
            catch
            {
            }
        }

        return result
            .OrderByDescending(x => x.LastWriteUtc)
            .Take(3000)
            .ToList();
    }

    private static List<FileRecord> CollectCandidateFiles(
        List<PrefetchRecord> prefetch,
        List<DetectionRule> rules)
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddRoot(string? value)
        {
            if (!string.IsNullOrWhiteSpace(value) && Directory.Exists(value))
            {
                roots.Add(value);
            }
        }

        AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        AddRoot(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
        AddRoot(Path.GetTempPath());
        AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));

        string[] extensions = { ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".com", ".scr", ".zip", ".rar", ".7z" };
        var files = new List<FileRecord>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string root in roots)
        {
            foreach (string file in EnumerateFilesLimited(root, depth: 2, maxFiles: 2500))
            {
                if (files.Count >= 5000) break;

                string extension = Path.GetExtension(file);
                if (!extensions.Contains(extension, StringComparer.OrdinalIgnoreCase)) continue;
                if (!seen.Add(file)) continue;

                try
                {
                    var info = new FileInfo(file);
                    if (!info.Exists) continue;

                    bool customInteresting =
                        rules.Any(rule =>
                            RuleHintsFile(rule, info.Name, info.FullName));

                    bool recent =
                        info.LastWriteTimeUtc >= DateTime.UtcNow.AddDays(-120);

                    bool riskDirectory =
                        info.FullName.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                        info.FullName.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase) ||
                        info.FullName.Contains("\\Desktop\\", StringComparison.OrdinalIgnoreCase);

                    if (!customInteresting && !recent && !riskDirectory) continue;

                    string? sha256 = null;
                    if (info.Length <= 250L * 1024L * 1024L)
                    {
                        sha256 = TrySha256(info.FullName);
                    }

                    (bool signed, string? signer) = TrySigner(info.FullName);
                    DateTime? executionEvidence =
                        FindPrefetchEvidence(info.Name, prefetch);

                    files.Add(new FileRecord
                    {
                        Name = info.Name,
                        Path = info.FullName,
                        Extension = info.Extension,
                        Size = info.Length,
                        CreatedUtc = SafeDate(info.CreationTimeUtc),
                        LastWriteUtc = SafeDate(info.LastWriteTimeUtc),
                        Sha256 = sha256,
                        Signed = signed,
                        SignerSubject = signer,
                        PrefetchEvidenceUtc = executionEvidence,
                        CompilationTimeUtc = TryPeCompileTimeUtc(info.FullName),
                        RandomLikeName = LooksRandomFileName(info.Name),
                        ArchiveEntries = info.Extension.Equals(".zip", StringComparison.OrdinalIgnoreCase)
                            ? TryListZipEntries(info.FullName)
                            : new List<string>(),
                        DriveType = GetDriveType(info.FullName)
                    });
                }
                catch
                {
                }
            }
        }

        return files;
    }

    private static bool RuleHintsFile(DetectionRule rule, string name, string fullPath)
    {
        string pattern = (rule.Pattern ?? "").Trim();

        if (string.IsNullOrWhiteSpace(pattern)) return false;

        return rule.Type switch
        {
            "filename_contains" =>
                name.Contains(pattern, StringComparison.OrdinalIgnoreCase),

            "path_contains" =>
                fullPath.Contains(pattern, StringComparison.OrdinalIgnoreCase),

            "sha256" => true,

            _ => false
        };
    }

    private static IEnumerable<string> EnumerateFilesLimited(string root, int depth, int maxFiles)
    {
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((root, 0));
        int yielded = 0;

        while (queue.Count > 0 && yielded < maxFiles)
        {
            (string current, int currentDepth) = queue.Dequeue();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(current);
            }
            catch
            {
                continue;
            }

            foreach (string file in files)
            {
                yield return file;
                yielded++;
                if (yielded >= maxFiles) yield break;
            }

            if (currentDepth >= depth) continue;

            IEnumerable<string> directories;
            try
            {
                directories = Directory.EnumerateDirectories(current);
            }
            catch
            {
                continue;
            }

            foreach (string directory in directories.Take(150))
            {
                queue.Enqueue((directory, currentDepth + 1));
            }
        }
    }

    private static DateTime? FindPrefetchEvidence(
        string fileName,
        List<PrefetchRecord> prefetch)
    {
        string executable =
            Path.GetFileNameWithoutExtension(fileName);

        return prefetch
            .Where(x =>
                x.Name.StartsWith(
                    executable + "-",
                    StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(x => x.LastWriteUtc)
            .Select(x => (DateTime?)x.LastWriteUtc)
            .FirstOrDefault();
    }

    private static List<ProcessRecord> CollectProcesses()
    {
        var result = new List<ProcessRecord>();
        var hashed = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        foreach (Process process in Process.GetProcesses())
        {
            try
            {
                string? path = process.MainModule?.FileName;
                string? hash = null;
                bool signed = false;
                string? signer = null;

                if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                {
                    if (!hashed.TryGetValue(path, out hash))
                    {
                        hash = new FileInfo(path).Length <= 250L * 1024L * 1024L
                            ? TrySha256(path)
                            : null;

                        hashed[path] = hash;
                    }

                    (signed, signer) = TrySigner(path);
                }

                result.Add(new ProcessRecord
                {
                    Pid = process.Id,
                    Name = process.ProcessName,
                    Path = path,
                    Sha256 = hash,
                    Signed = signed,
                    SignerSubject = signer,
                    StartTimeUtc = TryGetStartTime(process)
                });
            }
            catch
            {
                result.Add(new ProcessRecord
                {
                    Pid = process.Id,
                    Name = process.ProcessName
                });
            }
            finally
            {
                process.Dispose();
            }
        }

        return result;
    }

    private static List<ServiceRecord> CollectServices()
    {
        var result = new List<ServiceRecord>();

        using var searcher =
            new ManagementObjectSearcher(
                "SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_Service");

        foreach (ManagementObject item in searcher.Get())
        {
            result.Add(new ServiceRecord
            {
                Name = Convert.ToString(item["Name"]) ?? "",
                DisplayName = Convert.ToString(item["DisplayName"]) ?? "",
                State = Convert.ToString(item["State"]) ?? "",
                StartMode = Convert.ToString(item["StartMode"]) ?? "",
                PathName = Convert.ToString(item["PathName"]) ?? ""
            });
        }

        return result;
    }

    private static List<DriverRecord> CollectDrivers()
    {
        var result = new List<DriverRecord>();

        using var searcher =
            new ManagementObjectSearcher(
                "SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_SystemDriver");

        foreach (ManagementObject item in searcher.Get())
        {
            string pathName =
                Convert.ToString(item["PathName"]) ?? "";

            string resolvedPath =
                ResolveDriverPath(pathName);

            string? sha256 = null;
            bool signed = false;
            string? signer = null;

            if (
                !string.IsNullOrWhiteSpace(resolvedPath) &&
                File.Exists(resolvedPath))
            {
                try
                {
                    FileInfo info = new(resolvedPath);
                    if (info.Length <= 64L * 1024L * 1024L)
                        sha256 = TrySha256(resolvedPath);
                }
                catch
                {
                }

                (signed, signer) =
                    TrySigner(resolvedPath);
            }

            result.Add(new DriverRecord
            {
                Name = Convert.ToString(item["Name"]) ?? "",
                DisplayName = Convert.ToString(item["DisplayName"]) ?? "",
                State = Convert.ToString(item["State"]) ?? "",
                StartMode = Convert.ToString(item["StartMode"]) ?? "",
                PathName = pathName,
                ResolvedPath = resolvedPath,
                Sha256 = sha256,
                Signed = signed,
                SignerSubject = signer
            });
        }

        return result;
    }

    private static string ResolveDriverPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";

        string path = value.Trim().Trim('"');

        int exeIndex =
            path.IndexOf(
                ".sys",
                StringComparison.OrdinalIgnoreCase);

        if (exeIndex >= 0)
            path = path[..(exeIndex + 4)];

        string windows =
            Environment.GetFolderPath(
                Environment.SpecialFolder.Windows);

        if (path.StartsWith(
                @"\SystemRoot\",
                StringComparison.OrdinalIgnoreCase))
        {
            path = Path.Combine(
                windows,
                path[@"\SystemRoot\".Length..]);
        }
        else if (path.StartsWith(
                     @"\??\",
                     StringComparison.OrdinalIgnoreCase))
        {
            path = path[4..];
        }
        else if (
            path.StartsWith(
                @"System32\",
                StringComparison.OrdinalIgnoreCase))
        {
            path = Path.Combine(
                windows,
                path);
        }

        try
        {
            return Path.GetFullPath(
                Environment.ExpandEnvironmentVariables(path));
        }
        catch
        {
            return path;
        }
    }

    private static List<StartupRecord> CollectStartupEntries()
    {
        var result = new List<StartupRecord>();

        CollectRunKey(
            Microsoft.Win32.Registry.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU Run",
            result);

        CollectRunKey(
            Microsoft.Win32.Registry.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU RunOnce",
            result);

        CollectRunKey(
            Microsoft.Win32.Registry.LocalMachine,
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM Run",
            result);

        CollectRunKey(
            Microsoft.Win32.Registry.LocalMachine,
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM RunOnce",
            result);

        string startupFolder =
            Environment.GetFolderPath(Environment.SpecialFolder.Startup);

        if (Directory.Exists(startupFolder))
        {
            foreach (string file in Directory.EnumerateFiles(startupFolder))
            {
                result.Add(new StartupRecord
                {
                    Source = "Startup folder",
                    Name = Path.GetFileName(file),
                    Command = file
                });
            }
        }

        return result;
    }

    private static void CollectRunKey(
        RegistryKey hive,
        string subKey,
        string source,
        List<StartupRecord> result)
    {
        using RegistryKey? key = hive.OpenSubKey(subKey);
        if (key == null) return;

        foreach (string name in key.GetValueNames())
        {
            result.Add(new StartupRecord
            {
                Source = source,
                Name = name,
                Command = Convert.ToString(key.GetValue(name)) ?? ""
            });
        }
    }

    private static string? TrySha256(string path)
    {
        try
        {
            using FileStream stream =
                new(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);

            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    private static bool LooksRandomFileName(string fileName)
    {
        try
        {
            string stem = Path.GetFileNameWithoutExtension(fileName);

            if (IsGenericInstallerStem(stem))
                return false;

            stem = System.Text.RegularExpressions.Regex.Replace(
                stem,
                @"\.(zip|rar|7z|pdf|jpg|jpeg|png|txt)$",
                "",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            if (stem.Length < 4 || stem.Length > 28)
                return false;

            if (!stem.All(char.IsLetterOrDigit))
                return false;

            int letters = stem.Count(char.IsLetter);
            int digits = stem.Count(char.IsDigit);
            int vowels = stem.Count(ch => "aeiouAEIOU".Contains(ch));
            int distinct = stem.ToUpperInvariant().Distinct().Count();
            bool allUpperOrDigits = stem.All(ch =>
                char.IsDigit(ch) || char.IsUpper(ch));

            double vowelRatio = letters > 0
                ? (double)vowels / letters
                : 0;

            if (stem.Length <= 5)
            {
                return
                    allUpperOrDigits &&
                    distinct >= Math.Max(4, stem.Length - 1) &&
                    (digits >= 1 || vowels == 0) &&
                    vowelRatio <= 0.25;
            }

            if (
                allUpperOrDigits &&
                distinct >= Math.Min(6, stem.Length - 1) &&
                (
                    digits >= 1
                        ? vowelRatio <= 0.35
                        : vowelRatio <= 0.12
                ))
            {
                return true;
            }

            if (
                stem.Length >= 8 &&
                stem.Length <= 18 &&
                digits == 0 &&
                letters == stem.Length &&
                distinct >= 7 &&
                vowelRatio <= 0.22)
            {
                return true;
            }

            return
                stem.Length >= 10 &&
                letters >= 6 &&
                digits >= 2 &&
                distinct >= 8;
        }
        catch
        {
            return false;
        }
    }


    private static bool IsGenericInstallerStem(string value)
    {
        string stem = (value ?? "").Trim().ToLowerInvariant();

        return stem is
            "installer" or
            "install" or
            "setup" or
            "setup64" or
            "setup32" or
            "updater" or
            "update" or
            "uninstall" or
            "uninstaller" or
            "bootstrapper" or
            "launcherinstaller";
    }

    private static List<string> TryListZipEntries(string path)
    {
        var result = new List<string>();

        try
        {
            using var archive = System.IO.Compression.ZipFile.OpenRead(path);

            foreach (var entry in archive.Entries.Take(400))
            {
                string name = entry.FullName?.Trim() ?? "";
                if (!string.IsNullOrWhiteSpace(name))
                    result.Add(name);
            }
        }
        catch
        {
        }

        return result;
    }

    private static DateTime? TryPeCompileTimeUtc(string path)
    {
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);

            if (stream.Length < 256)
                return null;

            using var reader = new BinaryReader(stream);

            if (reader.ReadUInt16() != 0x5A4D)
                return null;

            stream.Position = 0x3C;
            int peOffset = reader.ReadInt32();

            if (peOffset <= 0 || peOffset + 12 > stream.Length)
                return null;

            stream.Position = peOffset;
            if (reader.ReadUInt32() != 0x00004550)
                return null;

            _ = reader.ReadUInt16();
            _ = reader.ReadUInt16();
            uint timestamp = reader.ReadUInt32();

            if (timestamp == 0)
                return null;

            DateTime utc = DateTimeOffset
                .FromUnixTimeSeconds(timestamp)
                .UtcDateTime;

            if (utc.Year < 1990 || utc > DateTime.UtcNow.AddYears(2))
                return null;

            return utc;
        }
        catch
        {
            return null;
        }
    }

    private static (bool Signed, string? Subject) TrySigner(string path)
    {
        (bool trusted, string subject) =
            AuthenticodeVerifier.Verify(path);

        return (
            trusted,
            string.IsNullOrWhiteSpace(subject)
                ? null
                : subject
        );
    }

    private static DateTime? TryGetStartTime(Process process)
    {
        try
        {
            return process.StartTime.ToUniversalTime();
        }
        catch
        {
            return null;
        }
    }

    private static DateTime? SafeDate(DateTime value)
    {
        if (value.Year < 1980 || value.Year > 9998) return null;
        return value;
    }

    private static string GetDriveType(string filePath)
    {
        try
        {
            string? root = Path.GetPathRoot(filePath);
            if (string.IsNullOrWhiteSpace(root)) return "Unknown";
            return new DriveInfo(root).DriveType.ToString();
        }
        catch
        {
            return "Unknown";
        }
    }
}

internal sealed class AgentConfig
{
    public string Token { get; set; } = "";
    public string ServerUrl { get; set; } = "";
}

internal sealed class RulesResponse
{
    public long AnalysisId { get; set; }
    public List<DetectionRule> Rules { get; set; } = new();
    public List<RustThreatIndicator> ThreatCatalog { get; set; } = new();
}

internal sealed class RustThreatIndicator
{
    public string Name { get; set; } = "";
    public List<string> Aliases { get; set; } = new();
    public List<string> Domains { get; set; } = new();
    public List<string> DiscordInvites { get; set; } = new();
    public string Severity { get; set; } = "high";
}

internal sealed class DetectionRule
{
    public long Id { get; set; }
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string Pattern { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Description { get; set; } = "";
}

internal sealed class ScanReport
{
    public string AgentVersion { get; set; } = "";
    public DateTime CollectedAtUtc { get; set; }
    public MachineRecord Machine { get; set; } = new();
    public List<UsbDeviceRecord> UsbCurrent { get; set; } = new();
    public List<UsbHistoryRecord> UsbHistory { get; set; } = new();
    public List<UsbDeviceEventRecord> UsbTimeline { get; set; } = new();
    public List<SerialDeviceRecord> SerialDevices { get; set; } = new();
    public HardwareSummaryRecord HardwareSummary { get; set; } = new();
    public List<ProcessRecord> Processes { get; set; } = new();
    public List<PrefetchRecord> Prefetch { get; set; } = new();
    public List<PrefetchExecutionRecord> PrefetchExecutions { get; set; } = new();
    public List<ServiceRecord> Services { get; set; } = new();
    public List<DriverRecord> Drivers { get; set; } = new();
    public List<StartupRecord> Startup { get; set; } = new();
    public List<FileRecord> Files { get; set; } = new();
    public List<PeInspectionRecord> PeInspections { get; set; } = new();
    public List<ZoneIdentifierRecord> ZoneIdentifiers { get; set; } = new();
    public List<AlternateDataStreamRecord> AlternateDataStreams { get; set; } = new();
    public List<AutorunIntegrityRecord> AutorunIntegrity { get; set; } = new();
    public List<ProcessModuleIntegrityRecord> ProcessModuleIntegrity { get; set; } = new();
    public List<ProcessMemoryIntegrityRecord> ProcessMemoryIntegrity { get; set; } = new();
    public List<WindowProtectionRecord> ProtectedWindows { get; set; } = new();
    public List<BamRecord> Bam { get; set; } = new();
    public List<UserAssistRecord> UserAssist { get; set; } = new();
    public List<MuiCacheRecord> MuiCache { get; set; } = new();
    public List<PcaRecord> Pca { get; set; } = new();
    public List<AmcacheExecutionRecord> Amcache { get; set; } = new();
    public List<ShimCacheRecord> ShimCache { get; set; } = new();
    public List<SetupApiUsbRecord> SetupApiUsb { get; set; } = new();
    public List<PowerShellRuleHit> PowerShellHits { get; set; } = new();
    public List<PowerShellArtifactRecord> PowerShellArtifacts { get; set; } = new();
    public List<PrefetchIntegrityRecord> PrefetchIntegrity { get; set; } = new();
    public List<VolumeRecord> HiddenVolumes { get; set; } = new();
    public List<EventLogSignalRecord> LogClearSignals { get; set; } = new();
    public List<ProcessCreationRecord> ProcessCreationEvents { get; set; } = new();
    public List<DefenderDetectionRecord> DefenderDetections { get; set; } = new();
    public List<RecentShortcutRecord> RecentShortcuts { get; set; } = new();
    public List<CrashArtifactRecord> CrashArtifacts { get; set; } = new();
    public List<SecurityProductRecord> SecurityProducts { get; set; } = new();
    public List<RecycleBinRecord> RecycleBin { get; set; } = new();
    public VmEnvironmentRecord VmEnvironment { get; set; } = new();
    public List<BrowserDownloadRecord> BrowserDownloads { get; set; } = new();
    public List<BrowserHistoryRecord> BrowserHistorySignals { get; set; } = new();
    public List<RecoveredBrowserArtifact> BrowserRecoveredArtifacts { get; set; } = new();
    public List<NetworkIndicatorRecord> NetworkIndicators { get; set; } = new();
    public List<DeletedUsnRecord> DeletedUsnRecords { get; set; } = new();
    public List<ExtensionMismatchRecord> ExtensionMismatches { get; set; } = new();
    public List<DefenderExclusionRecord> DefenderExclusions { get; set; } = new();
    public List<BootIntegrityRecord> BootIntegrity { get; set; } = new();
    public ActivityHistoryState ActivityHistory { get; set; } = new();
    public List<SystemTimeChangeRecord> SystemTimeChanges { get; set; } = new();
    public List<VirtualDiskRecord> VirtualDisks { get; set; } = new();
    public List<RustModuleRecord> RustModules { get; set; } = new();
    public List<UsnJournalStateRecord> UsnJournalState { get; set; } = new();
    public List<UsnActivityRecord> UsnActivity { get; set; } = new();
    public List<SystemIntegrityExpansionRecord> SystemIntegrityExpansion { get; set; } = new();
    public SystemArtifactRecord SystemArtifacts { get; set; } = new();
    public List<string> Errors { get; set; } = new();
}

internal sealed class MachineRecord
{
    public string MachineName { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public bool Is64BitOs { get; set; }
    public string Fingerprint { get; set; } = "";
}

internal sealed class UsbDeviceRecord
{
    public string Name { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string PnpDeviceId { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string Status { get; set; } = "";
    public bool Present { get; set; }
}

internal sealed class UsbHistoryRecord
{
    public string DeviceClass { get; set; } = "";
    public string InstanceId { get; set; } = "";
    public string FriendlyName { get; set; } = "";
    public string DeviceDescription { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public bool Present { get; set; }
    public DateTime? LastConnectedUtc { get; set; }
    public DateTime? LastDisconnectedUtc { get; set; }
    public string TimelineSource { get; set; } = "";
}

internal sealed class SerialDeviceRecord
{
    public string Name { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string PnpDeviceId { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string Status { get; set; } = "";
    public string PnpClass { get; set; } = "";
    public string Service { get; set; } = "";
}

internal sealed class FileRecord
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Extension { get; set; } = "";
    public long Size { get; set; }
    public DateTime? CreatedUtc { get; set; }
    public DateTime? LastWriteUtc { get; set; }
    public string? Sha256 { get; set; }
    public bool Signed { get; set; }
    public string? SignerSubject { get; set; }
    public DateTime? PrefetchEvidenceUtc { get; set; }
    public DateTime? CompilationTimeUtc { get; set; }
    public bool RandomLikeName { get; set; }
    public List<string> ArchiveEntries { get; set; } = new();
    public string DriveType { get; set; } = "";
}

internal sealed class ProcessRecord
{
    public int Pid { get; set; }
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public string? Sha256 { get; set; }
    public bool Signed { get; set; }
    public string? SignerSubject { get; set; }
    public DateTime? StartTimeUtc { get; set; }
}

internal sealed class PrefetchRecord
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public DateTime LastWriteUtc { get; set; }
    public long Size { get; set; }
}

internal sealed class ServiceRecord
{
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string State { get; set; } = "";
    public string StartMode { get; set; } = "";
    public string PathName { get; set; } = "";
}

internal sealed class DriverRecord
{
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string State { get; set; } = "";
    public string StartMode { get; set; } = "";
    public string PathName { get; set; } = "";
    public string ResolvedPath { get; set; } = "";
    public string? Sha256 { get; set; }
    public bool Signed { get; set; }
    public string? SignerSubject { get; set; }
}

internal sealed class StartupRecord
{
    public string Source { get; set; } = "";
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
}
