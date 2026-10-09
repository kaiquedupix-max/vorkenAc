using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows.Forms;

namespace Vorken.Agent;

internal sealed partial class AgentMainForm : Form
{
    private const string PrivacyUrl = "https://vorkenac.guerrafriarust.com.br/privacy";
    private const string TermsUrl = "https://vorkenac.guerrafriarust.com.br/terms";
    private readonly UiAudio _uiAudio = new();

    private readonly string[] _args;
    private readonly AnimatedSurface _surface = new();
    private readonly Panel _header = new();
    private readonly Panel _nav = new();
    private readonly Label _headerStatus = new();
    private readonly RichTextBox _activityBox = new();
    private readonly Panel _progressTrack = new();
    private readonly Panel _progressFill = new();
    private readonly Label _progressPercentLabel = new();
    private readonly Label _progressEtaLabel = new();
    private readonly Label _elapsedLabel = new();
    private readonly Label _artifactCountLabel = new();
    private readonly Label _deviceCountLabel = new();
    private readonly Button _startButton = new();
    private readonly Button _closeButton = new();
    private readonly System.Windows.Forms.Timer _motionTimer = new();
    private readonly System.Windows.Forms.Timer _scanTimer = new();
    private readonly System.Windows.Forms.Timer _fadeTimer = new();
    private readonly System.Windows.Forms.Timer _clientResultPollTimer = new();

    private readonly List<Label> _stepStateLabels = new();
    private readonly List<string> _activityLines = new();
    private readonly List<AgentFindingSnapshot> _visibleFindings = new();
    private readonly HashSet<Button> _enhancedButtons = new();
    private RemoteSupportClient? _remoteSupport;
    private Label? _remoteStatusLabel;

    private Panel? _evidenceDetailPanel;
    private DateTime _scanStartedAt;
    private AgentRunResult? _lastRun;
    private bool _running;
    private bool _finished;
    private bool _termsAccepted;
    private bool _soundEnabled = true;
    private float _motion;
    private int _progressPercent;
    private int _artifactCount;
    private int _devicesSeen;

    // Same core palette used by website/public/styles.css.
    private static readonly Color Background = Color.FromArgb(11, 17, 27);       // #070a0d
    private static readonly Color Header = Color.FromArgb(11, 17, 27);           // #070a0d
    private static readonly Color Surface = Color.FromArgb(16, 27, 43);         // #0d1217
    private static readonly Color SurfaceAlt = Color.FromArgb(20, 34, 56);      // #111820
    private static readonly Color Border = Color.FromArgb(35, 53, 78);          // #202b35
    private static readonly Color BorderBright = Color.FromArgb(59, 130, 246);  // #26b88e
    private static readonly Color Accent = Color.FromArgb(37, 99, 235);        // #53f0bd
    private static readonly Color AccentSoft = Color.FromArgb(59, 130, 246);    // #26b88e
    private static readonly Color Blue = Color.FromArgb(99, 169, 255);          // #63a9ff
    private static readonly Color TextPrimary = Color.FromArgb(238, 244, 247);  // #eef4f7
    private static readonly Color TextSecondary = Color.FromArgb(130, 146, 159);// #82929f
    private static readonly Color TextDim = Color.FromArgb(101, 121, 133);      // #657985
    private static readonly Color Warning = Color.FromArgb(255, 200, 87);       // #ffc857
    private static readonly Color Danger = Color.FromArgb(255, 102, 117);       // #ff6675
    private static readonly Color Success = Color.FromArgb(82, 219, 174);       // #53f0bd


    private static readonly ManualToolDefinition[] ManualTools =
    {
        new(
            "ToolsDownloader++",
            "Suite all-in-one da detect.ac para baixar as ferramentas forenses gratuitas.",
            "https://detect.ac/tool/ToolsDownloader++"),
        new(
            "Autoruns++",
            "Revisão de inicialização, assinaturas digitais e modificações relacionadas ao USN.",
            "https://detect.ac/tool/Autoruns++"),
        new(
            "StringExplorer++",
            "Exploração de strings, datas de compilação, entropia e indicadores anômalos.",
            "https://detect.ac/tool/StringExplorer++"),
        new(
            "MOSS 2.0",
            "Monitor de integridade em tempo real voltado ao Rainbow Six Siege.",
            "https://detect.ac/tool/MOSS-2.0"),
        new(
            "WinPrefetchView++",
            "Análise de Prefetch com detecções de bypass, assinaturas e YARA.",
            "https://detect.ac/tool/WinPrefetchView++"),
        new(
            "USBDeview++",
            "Correlação de dispositivos USB, histórico de conexão e firmware.",
            "https://detect.ac/tool/USBDeview++"),
        new(
            "SavedFilesViewer++",
            "Lista arquivos salvos em disco e correlaciona artefatos de download.",
            "https://detect.ac/tool/SavedFilesViewer++"),
        new(
            "SRUMExplorer++",
            "Mapeia caminhos, serviços, uso de rede, timestamps e artefatos SRUM.",
            "https://detect.ac/tool/SRUMExplorer++"),
        new(
            "PowerShellParser++",
            "Coleta e filtragem de artefatos de histórico do PowerShell.",
            "https://detect.ac/tool/PowerShellParser++"),
        new(
            "PathsParser++",
            "Parser de caminhos com YARA e visualização do USN Journal.",
            "https://detect.ac/tool/PathsParser++"),
        new(
            "MFTExplorer++",
            "Visualização do $MFT, ADS suspeitos e rastros históricos de arquivos.",
            "https://detect.ac/tool/MFTExplorer++"),
        new(
            "KernelLiveDump++",
            "Captura e análise de RAM kernel/user-mode com busca por strings.",
            "https://detect.ac/tool/KernelLiveDump++"),
        new(
            "JournalTrace++",
            "Análise de USN Journal com filtros por razão, palavras-chave e bypasses.",
            "https://detect.ac/tool/JournalTrace++"),
        new(
            "CrashedFileViewer++",
            "Consolida artefatos de crash do Windows e alterações relacionadas no USN.",
            "https://detect.ac/tool/CrashedFileViewer++"),
        new(
            "BrowsingHistoryView++",
            "Consolida histórico de navegação e destaca domínios para revisão.",
            "https://detect.ac/tool/BrowsingHistoryView++"),
        new(
            "BrowserDownloadsView++",
            "Consolida histórico de downloads, USN e verificações YARA.",
            "https://detect.ac/tool/BrowserDownloadsView++"),
        new(
            "BamParser++",
            "Extrai histórico de execução e timestamps do Background Activity Monitor.",
            "https://detect.ac/tool/BamParser++"),
        new(
            "AmcacheParser++",
            "Parser de Amcache com YARA, SHA1, filtros e apoio à reputação.",
            "https://detect.ac/tool/AmcacheParser++")
    };

    internal AgentMainForm(string[] args)
    {
        _args = args;

        string executableTitle =
            Path.GetFileNameWithoutExtension(
                Environment.ProcessPath ??
                Application.ExecutablePath);

        Text =
            executableTitle.StartsWith(
                "Vorken AntiCheat - ",
                StringComparison.OrdinalIgnoreCase)
                ? executableTitle
                : "Vorken AntiCheat";

        try
        {
            Icon? executableIcon =
                Icon.ExtractAssociatedIcon(
                    Application.ExecutablePath);

            if (executableIcon != null)
                Icon = executableIcon;
        }
        catch
        {
        }

        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1440, 900);
        MinimumSize = new Size(1280, 800);
        BackColor = Background;
        ForeColor = TextPrimary;
        Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point);
        FormBorderStyle = FormBorderStyle.None;
        DoubleBuffered = true;
        Opacity = 0d;

        BuildShell();
        WireUiSounds(this);
        FormClosed += (_, _) => _uiAudio.Dispose();
        ShowLanguageGate();

        _motionTimer.Interval = 24;
        _motionTimer.Tick += MotionTimer_Tick;
        _motionTimer.Start();

        _scanTimer.Interval = 1000;
        _scanTimer.Tick += ScanTimer_Tick;

        _fadeTimer.Interval = 16;
        _fadeTimer.Tick += FadeTimer_Tick;

        _clientResultPollTimer.Interval = 5000;
        _clientResultPollTimer.Tick += ClientResultPollTimer_Tick;

        Shown += (_, _) =>
        {
            UpdateWindowRegion();
            _fadeTimer.Start();
        };

        SizeChanged += (_, _) => UpdateWindowRegion();
        FormClosing += OnFormClosing;
    }

    private void BuildShell()
    {
        var outer = new BorderFrame
        {
            Dock = DockStyle.Fill,
            BackColor = Background,
            BorderColor = BorderBright
        };

        _header.Dock = DockStyle.Top;
        _header.Height = 88;
        _header.BackColor = Color.FromArgb(11, 20, 33);
        _header.MouseDown += Header_MouseDown;
        AttachRoundedRegion(_header, 16);

        var brandMark = new PictureBox
        {
            Image = LoadBrandMark(),
            SizeMode = PictureBoxSizeMode.Zoom,
            AutoSize = false,
            Size = new Size(52, 52),
            Location = new Point(28, 14),
            BackColor = Color.Transparent,
            ForeColor = Color.FromArgb(255, 255, 255),
            Font = new Font("Segoe UI", 22F, FontStyle.Bold)
        };

        AttachRoundedRegion(brandMark, 7);

        var brandName = new Label
        {
            Text = "VORKEN",
            AutoSize = true,
            Location = new Point(88, 21),
            Font = new Font("Segoe UI", 21F, FontStyle.Bold),
            ForeColor = TextPrimary,
            BackColor = Color.Transparent
        };

        var brandCaption = new Label
        {
            Text = "ANTI CHEAT",
            AutoSize = true,
            Location = new Point(226, 31),
            Font = new Font("Consolas", 9F, FontStyle.Bold),
            ForeColor = Accent,
            BackColor = Color.Transparent
        };

        _nav.Location = new Point(330, 22);
        _nav.Size = new Size(840, 48);
        _nav.BackColor = Color.Transparent;
        _nav.Visible = false;

        AddNavButton("⌂", L("Início", "Inicio", "Home"), 0, () => ShowCompletionHome());
        AddNavButton("⚙", L("Análise", "Análisis", "Analysis"), 1, ShowAnalysisSummaryView);
        AddNavButton("≡", L("Resultados", "Resultados", "Results"), 2, () =>
        {
            if (_lastRun is not null)
                ShowDetailedResultsView(_lastRun);
        });
        AddNavButton("◷", L("Histórico", "Historial", "History"), 3, ShowHistoryView);
        AddNavButton("⊞", L("Análise Manual", "Análisis Manual", "Manual Analysis"), 4, ShowManualAnalysisView);
        AddNavButton("⚙", L("Configurações", "Configuración", "Settings"), 5, ShowSettingsView);
        AddNavButton("◉", L("Suporte", "Soporte", "Support"), 6, ShowRemoteSupportView);

        _headerStatus.Text = "●  READY";
        _headerStatus.AutoSize = false;
        _headerStatus.Size = new Size(140, 36);
        _headerStatus.Location = new Point(1020, 35);
        _headerStatus.TextAlign = ContentAlignment.MiddleCenter;
        _headerStatus.Font = new Font("Consolas", 9F, FontStyle.Bold);
        _headerStatus.ForeColor = Accent;
        _headerStatus.BackColor = Color.FromArgb(20, 40, 71);
        AttachRoundedRegion(_headerStatus, 8);
        _headerStatus.Cursor = Cursors.Default;
        _headerStatus.Click += async (_, _) =>
        {
            if (_remoteSupport is not null)
                await StopRemoteSupportAsync();
        };

        var minButton = MakeWindowButton("—", _header.ClientSize.Width - 120);
        minButton.Click += (_, _) => WindowState = FormWindowState.Minimized;

        var maxButton = MakeWindowButton("□", _header.ClientSize.Width - 82);
        maxButton.Click += (_, _) =>
            WindowState = WindowState == FormWindowState.Maximized
                ? FormWindowState.Normal
                : FormWindowState.Maximized;

        var exitButton = MakeWindowButton("×", _header.ClientSize.Width - 44);
        exitButton.Click += (_, _) => Close();

        var divider = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 1,
            BackColor = Border
        };

        _header.Controls.Add(brandMark);
        _header.Controls.Add(brandName);
        _header.Controls.Add(brandCaption);
        _header.Controls.Add(_nav);
        _header.Controls.Add(_headerStatus);
        _header.Controls.Add(minButton);
        _header.Controls.Add(maxButton);
        _header.Controls.Add(exitButton);
        _header.Controls.Add(divider);

        _surface.Dock = DockStyle.Fill;
        _surface.BackColor = Background;
        AttachRoundedRegion(_surface, 16);

        outer.Controls.Add(_surface);
        outer.Controls.Add(_header);
        Controls.Add(outer);

        void LayoutShell(object? sender, EventArgs args)
        {
            _headerStatus.Left = Math.Max(840, ClientSize.Width - 260);
            _nav.Left = ClientSize.Width >= 1360 ? 330 : 240;
            brandCaption.Visible = ClientSize.Width >= 1360;
            LayoutGuidedNavigation();
            minButton.Left = _header.ClientSize.Width - 120;
            maxButton.Left = _header.ClientSize.Width - 82;
            exitButton.Left = _header.ClientSize.Width - 44;
            minButton.BringToFront();
            maxButton.BringToFront();
            exitButton.BringToFront();
        }
        Resize += LayoutShell;
        _header.SizeChanged += LayoutShell;
        LayoutShell(this, EventArgs.Empty);
    }

    private GuidedWindowButton MakeWindowButton(string text, int x)
    {
        var button = new GuidedWindowButton
        {
            Kind = text == "\u00d7" ? 2 : text == "\u25a1" ? 1 : 0,
            Text = text,
            AccessibleName = text == "×" ? "Fechar" : text == "□" ? "Maximizar ou restaurar" : "Minimizar",
            Location = new Point(x, 10),
            Size = new Size(30, 24),
            BackColor = _header.BackColor,
            ForeColor = TextPrimary,
            TabStop = false
        };
        button.MouseEnter += (_, _) => PlayUiHover();
        button.Click += (_, _) => PlayUiClick();
        return button;
    }

    private void AddNavButton(string icon, string text, int index, Action action)
    {
        var button = new GuidedNavButton
        {
            Text = text,
            Symbol = index,
            Tag = index,
            Location = new Point(index * 118, 0),
            Size = new Size(114, 42),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.Transparent,
            ForeColor = TextSecondary,
            Font = new Font("Segoe UI", 10.5F),
            Cursor = Cursors.Hand
        };
        button.FlatAppearance.BorderSize = 0;
        button.Click += (_, _) =>
        {
            SetActiveNav(index);
            action();
        };
        _nav.Controls.Add(button);
        LayoutGuidedNavigation();
    }

    private void SetActiveNav(int index)
    {
        foreach (Control control in _nav.Controls)
        {
            if (control is not GuidedNavButton button)
                continue;

            bool active = Convert.ToInt32(button.Tag) == index;
            button.Selected = active;
            button.Invalidate();
        }
    }

    private static string L(string portuguese, string spanish, string english) =>
        AgentLocalization.Pick(portuguese, spanish, english);

    private void UpdateNavLanguage()
    {
        string[] icons = { "⌂", "⚙", "≡", "◷", "⊞", "⚙", "◉" };
        string[] labels =
        {
            L("Início", "Inicio", "Home"),
            L("Análise", "Análisis", "Analysis"),
            L("Resultados", "Resultados", "Results"),
            L("Histórico", "Historial", "History"),
            L("Análise Manual", "Análisis Manual", "Manual Analysis"),
            L("Configurações", "Configuración", "Settings"),
            L("Suporte", "Soporte", "Support")
        };

        foreach (Control control in _nav.Controls)
        {
            if (control is Button button && button.Tag is int index &&
                index >= 0 && index < labels.Length)
            {
                button.Text = labels[index];
            }
        }
        LayoutGuidedNavigation();
    }

    private void LayoutGuidedNavigation()
    {
        _nav.Width = Math.Max(600, _header.ClientSize.Width - _nav.Left - 144);
        int x = 0;
        foreach (var button in _nav.Controls.OfType<GuidedNavButton>())
        {
            int width = TextRenderer.MeasureText(button.Text, button.Font, Size.Empty, TextFormatFlags.SingleLine | TextFormatFlags.NoPadding).Width + 62;
            button.Bounds = new Rectangle(x, 0, width, 54);
            x += width + 2;
        }
        _nav.Height = 54;
    }

    private void ShowLanguageGate()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Idle;
        _nav.Visible = false;
        _termsAccepted = false;
        _finished = false;

        var badge = MakeBadge("LANGUAGE   ·   IDIOMA");
        badge.Location = new Point(44, 36);
        _surface.Controls.Add(badge);
        _surface.Controls.Add(MakeLabel(
            "Escolha seu idioma  ·  Elige tu idioma  ·  Choose your language",
            new Rectangle(44, 88, 1160, 58),
            27F,
            TextPrimary,
            FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            "A escolha será salva neste computador e poderá ser alterada nas configurações.",
            new Rectangle(47, 148, 1080, 30),
            10F,
            TextSecondary));

        var card = MakeCard(new Rectangle(44, 210, 1180, 500));
        card.CornerRadius = 20;
        card.Controls.Add(MakeSectionTitle("◉   VORKEN ANTI-CHEAT", 28, 24));

        AddLanguageChoice(
            card,
            AgentLanguage.Portuguese,
            "PT-BR",
            "Português",
            "Continuar em português",
            28);
        AddLanguageChoice(
            card,
            AgentLanguage.Spanish,
            "ES",
            "Español",
            "Continuar en español",
            402);
        AddLanguageChoice(
            card,
            AgentLanguage.English,
            "EN",
            "English",
            "Continue in English",
            776);

        _surface.Controls.Add(card);
        SetHeaderState("LANGUAGE", Accent);
    }

    private void AddLanguageChoice(
        Control parent,
        AgentLanguage language,
        string code,
        string title,
        string action,
        int x)
    {
        bool selected = AgentLocalization.Current == language;
        var panel = new BorderedPanel
        {
            Bounds = new Rectangle(x, 90, 346, 340),
            BackColor = selected ? Color.FromArgb(20, 40, 71) : Surface,
            BorderColor = selected ? AccentSoft : Border,
            CornerRadius = 18
        };
        panel.Controls.Add(MakeLabel(
            code,
            new Rectangle(24, 28, 290, 28),
            9F,
            Accent,
            FontStyle.Bold,
            "Consolas"));
        panel.Controls.Add(MakeLabel(
            title,
            new Rectangle(24, 78, 290, 52),
            25F,
            TextPrimary,
            FontStyle.Bold));
        panel.Controls.Add(MakeLabel(
            language switch
            {
                AgentLanguage.Spanish => "Términos, consentimiento y navegación en español.",
                AgentLanguage.English => "Terms, consent and navigation in English.",
                _ => "Termos, consentimento e navegação em português."
            },
            new Rectangle(24, 145, 290, 62),
            9.5F,
            TextSecondary));

        var button = new Button
        {
            Text = action + "  →",
            Bounds = new Rectangle(24, 245, 298, 58)
        };
        StylePrimaryButton(button);
        button.Click += (_, _) =>
        {
            AgentLocalization.Select(language);
            UpdateNavLanguage();
            ShowTermsGate();
        };
        panel.Controls.Add(button);
        parent.Controls.Add(panel);
    }

    private void ShowTermsGate()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Idle;
        _nav.Visible = false;
        _finished = false;

        var badge = MakeBadge(L(
            "ETAPA OBRIGATÓRIA   ·   CONSENTIMENTO",
            "PASO OBLIGATORIO   ·   CONSENTIMIENTO",
            "REQUIRED STEP   ·   CONSENT"));
        badge.Location = new Point(44, 28);

        _surface.Controls.Add(badge);
        _surface.Controls.Add(MakeLabel(
            L("Antes de começar, leia os termos.", "Antes de comenzar, lea los términos.", "Read the terms before you begin."),
            new Rectangle(44, 72, 850, 52),
            29F,
            TextPrimary,
            FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            L(
                "Role o documento até o final. O aceite libera o aplicativo e nenhuma análise começa automaticamente.",
                "Desplácese hasta el final. La aceptación habilita la aplicación y ningún análisis comienza automáticamente.",
                "Scroll to the end. Acceptance unlocks the application and no analysis starts automatically."),
            new Rectangle(47, 126, 960, 30),
            10.2F,
            TextSecondary));

        var termsCard = MakeCard(new Rectangle(44, 174, 820, 608));
        termsCard.CornerRadius = 18;
        termsCard.Controls.Add(MakeSectionTitle(L(
            "▤   TERMOS DE USO E CONSENTIMENTO",
            "▤   TÉRMINOS DE USO Y CONSENTIMIENTO",
            "▤   TERMS OF USE AND CONSENT"), 22, 18));

        var termsBox = new RichTextBox
        {
            Bounds = new Rectangle(20, 55, 780, 465),
            ReadOnly = true,
            DetectUrls = false,
            WordWrap = true,
            ScrollBars = RichTextBoxScrollBars.Vertical,
            BorderStyle = BorderStyle.None,
            BackColor = Color.FromArgb(3, 13, 19),
            ForeColor = Color.FromArgb(194, 210, 214),
            Font = new Font("Segoe UI", 9.8F),
            Text = AgentLocalization.Terms,
            TabStop = true
        };
        AttachRoundedRegion(termsBox, 14);
        termsCard.Controls.Add(termsBox);

        var scrollTrack = new Panel
        {
            Bounds = new Rectangle(22, 538, 510, 8),
            BackColor = Color.FromArgb(10, 41, 48)
        };
        AttachRoundedRegion(scrollTrack, 4);

        var scrollFill = new Panel
        {
            Bounds = new Rectangle(0, 0, 10, 8),
            BackColor = Accent
        };
        AttachRoundedRegion(scrollFill, 4);
        scrollTrack.Controls.Add(scrollFill);
        termsCard.Controls.Add(scrollTrack);

        var scrollHint = MakeLabel(
            L("↓  Role para continuar   ·   0%", "↓  Desplácese para continuar   ·   0%", "↓  Scroll to continue   ·   0%"),
            new Rectangle(548, 528, 250, 26),
            8F,
            Warning,
            FontStyle.Bold,
            "Consolas");
        scrollHint.TextAlign = ContentAlignment.MiddleRight;
        termsCard.Controls.Add(scrollHint);

        var officialTerms = new GuidedActionButton
        {
            Text = L("Termos oficiais ↗", "Términos oficiales ↗", "Official terms ↗"),
            Bounds = new Rectangle(22, 562, 170, 34)
        };
        StyleGhostButton(officialTerms);
        officialTerms.Click += (_, _) => OpenUrl(TermsUrl);
        termsCard.Controls.Add(officialTerms);

        var privacy = new GuidedActionButton
        {
            Text = L("Privacidade ↗", "Privacidad ↗", "Privacy ↗"),
            Bounds = new Rectangle(204, 562, 154, 34)
        };
        StyleGhostButton(privacy);
        privacy.Click += (_, _) => OpenUrl(PrivacyUrl);
        termsCard.Controls.Add(privacy);

        var actionCard = MakeCard(new Rectangle(890, 174, 334, 608));
        actionCard.CornerRadius = 18;
        actionCard.Controls.Add(MakeLabel(
            L("CONSENTIMENTO", "CONSENTIMIENTO", "CONSENT"),
            new Rectangle(24, 28, 240, 20),
            8.2F,
            Accent,
            FontStyle.Bold,
            "Consolas"));
        actionCard.Controls.Add(MakeLabel(
            L("Leitura clara.\nAceite consciente.", "Lectura clara.\nAceptación consciente.", "Clear reading.\nInformed consent."),
            new Rectangle(24, 66, 280, 76),
            19F,
            TextPrimary,
            FontStyle.Bold));
        actionCard.Controls.Add(MakeLabel(
            L(
                "O Vorken só será liberado após você chegar ao fim dos termos.",
                "Vorken solo se habilitará después de llegar al final de los términos.",
                "Vorken will only unlock after you reach the end of the terms."),
            new Rectangle(25, 158, 280, 58),
            9.5F,
            TextSecondary));

        string[] protections = AgentLocalization.Current switch
        {
            AgentLanguage.Spanish =>
            [
                "✓  Ningún análisis comienza solo",
                "✓  Alcance técnico presentado antes",
                "✓  Revisión humana de las alertas",
                "✓  Privacidad accesible en todo momento"
            ],
            AgentLanguage.English =>
            [
                "✓  No analysis starts by itself",
                "✓  Technical scope shown beforehand",
                "✓  Human review of alerts",
                "✓  Privacy available at any time"
            ],
            _ =>
            [
                "✓  Nenhuma análise inicia sozinha",
                "✓  Escopo técnico apresentado antes",
                "✓  Revisão humana dos alertas",
                "✓  Privacidade acessível a qualquer momento"
            ]
        };

        for (int i = 0; i < protections.Length; i++)
        {
            var row = new BorderedPanel
            {
                Bounds = new Rectangle(24, 240 + (i * 54), 286, 42),
                BackColor = Color.FromArgb(5, 21, 27),
                BorderColor = Color.FromArgb(18, 66, 76),
                CornerRadius = 12
            };
            row.Controls.Add(MakeLabel(
                protections[i],
                new Rectangle(14, 11, 258, 20),
                8.1F,
                i == 0 ? Accent : TextSecondary,
                FontStyle.Bold));
            actionCard.Controls.Add(row);
        }

        var acceptButton = new GuidedActionButton
        {
            Text = L("Role até o final para liberar", "Desplácese hasta el final", "Scroll to the end to unlock"),
            Bounds = new Rectangle(24, 488, 286, 62),
            Enabled = false
        };
        StylePrimaryButton(acceptButton);
        acceptButton.BackColor = Color.FromArgb(31, 73, 72);
        acceptButton.Click += (_, _) =>
        {
            if (!acceptButton.Enabled)
                return;

            _termsAccepted = true;
            ShowConsentView();
        };
        actionCard.Controls.Add(acceptButton);
        actionCard.Controls.Add(MakeLabel(
            L(
                "O aceite vale para esta execução do aplicativo.",
                "La aceptación es válida para esta ejecución de la aplicación.",
                "Acceptance applies to this application session."),
            new Rectangle(32, 562, 270, 20),
            7.1F,
            TextDim));

        void UpdateTermsProgress()
        {
            if (!termsBox.IsHandleCreated)
                return;

            string visibleText =
                (termsBox.Text ?? string.Empty).TrimEnd();

            int lastContentCharacter =
                Math.Max(0, visibleText.Length - 1);

            int visibleEndCharacter =
                termsBox.GetCharIndexFromPosition(
                    new Point(
                        Math.Max(1, termsBox.ClientSize.Width - 20),
                        Math.Max(1, termsBox.ClientSize.Height - 4)));

            int lastContentLine =
                termsBox.GetLineFromCharIndex(lastContentCharacter);

            int lastVisibleLine =
                termsBox.GetLineFromCharIndex(
                    Math.Max(0, visibleEndCharacter));

            Point lastContentPosition =
                termsBox.GetPositionFromCharIndex(
                    lastContentCharacter);

            // RichTextBox can leave the final line a few pixels below the old
            // threshold, especially with DPI scaling. Accept any of the three
            // equivalent bottom signals instead of depending on one pixel test.
            bool finalCharacterVisible =
                lastContentPosition.Y >= -termsBox.Font.Height &&
                lastContentPosition.Y <=
                    termsBox.ClientSize.Height + termsBox.Font.Height;

            bool nativeScrollAtBottom =
                IsRichTextBoxScrolledToBottom(termsBox);

            bool reachedBottom =
                nativeScrollAtBottom ||
                visibleEndCharacter >= lastContentCharacter ||
                lastVisibleLine >= lastContentLine ||
                finalCharacterVisible;

            int percent = reachedBottom
                ? 100
                : Math.Clamp(
                    (int)Math.Floor(
                        Math.Max(0, visibleEndCharacter) * 100d /
                        Math.Max(1, lastContentCharacter)),
                    0,
                    99);

            scrollFill.Width = Math.Max(
                10,
                scrollTrack.Width * percent / 100);
            scrollHint.Text = reachedBottom
                ? L("✓  Leitura concluída   ·   100%", "✓  Lectura completada   ·   100%", "✓  Reading complete   ·   100%")
                : L($"↓  Role para continuar   ·   {percent}%", $"↓  Desplácese para continuar   ·   {percent}%", $"↓  Scroll to continue   ·   {percent}%");
            scrollHint.ForeColor = reachedBottom
                ? Accent
                : Warning;

            acceptButton.Enabled = reachedBottom;

            if (reachedBottom)
            {
                acceptButton.Text = L("✓  Li e aceito os termos   →", "✓  He leído y acepto los términos   →", "✓  I have read and accept the terms   →");
                acceptButton.BackColor = Accent;
            }
            else
            {
                acceptButton.Text = L("Role até o final para liberar", "Desplácese hasta el final", "Scroll to the end to unlock");
                acceptButton.BackColor = Color.FromArgb(31, 73, 72);
            }
        }

        // VScroll may fire before the RichTextBox has applied the new viewport.
        // Evaluate on the next UI turn so dragging the scrollbar to the bottom
        // reliably unlocks the consent button.
        termsBox.VScroll += (_, _) =>
            BeginInvoke(UpdateTermsProgress);
        termsBox.MouseWheel += (_, _) =>
            BeginInvoke(UpdateTermsProgress);
        termsBox.KeyUp += (_, _) =>
            BeginInvoke(UpdateTermsProgress);
        termsBox.Resize += (_, _) =>
            BeginInvoke(UpdateTermsProgress);
        termsBox.HandleCreated += (_, _) =>
            BeginInvoke(UpdateTermsProgress);

        _surface.Controls.Add(termsCard);
        _surface.Controls.Add(actionCard);

        SetHeaderState(L("TERMOS", "TÉRMINOS", "TERMS"), Warning);
        termsBox.Focus();
    }

    private async void AcceptButton_Click(object? sender, EventArgs e)
    {
        if (_running || !_termsAccepted)
            return;

        _running = true;
        _finished = false;
        _lastRun = null;
        _scanStartedAt = DateTime.Now;
        _progressPercent = 3;
        _artifactCount = 0;
        _devicesSeen = 0;
        _activityLines.Clear();

        ShowProgressView();
        _scanTimer.Start();
        AppendStatus("[INIT] sessão validada");

        AgentRunResult result;

        try
        {
            result = await Task.Run(
                () => Program.RunAnalysisAsync(_args, AppendStatus));
        }
        catch (Exception ex)
        {
            AppendStatus("Falha inesperada: " + ex.Message);
            result = new AgentRunResult
            {
                ExitCode = 1,
                Error = ex.Message
            };
        }

        _running = false;
        _finished = true;
        _scanTimer.Stop();
        _lastRun = result;

        ShowResultsView(result);
    }

    private void ScanTimer_Tick(object? sender, EventArgs e)
    {
        if (!_running)
            return;

        if (_progressPercent < 92)
        {
            _progressPercent += _progressPercent < 35 ? 2 : 1;
            UpdateProgressUi();
        }

        TimeSpan elapsed = DateTime.Now - _scanStartedAt;
        _elapsedLabel.Text = elapsed.TotalMinutes >= 1
            ? $"{(int)elapsed.TotalMinutes:00} min {elapsed.Seconds:00} s"
            : $"00 min {elapsed.Seconds:00} s";
    }

    private void AppendStatus(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return;

        if (InvokeRequired)
        {
            BeginInvoke((Action)(() => AppendStatus(message)));
            return;
        }

        string normalized = message.Trim();
        string tag =
            normalized.StartsWith("✓", StringComparison.Ordinal)
                ? "[OK]"
                : normalized.StartsWith("!", StringComparison.Ordinal)
                    ? "[WARN]"
                    : normalized.Contains("Falha", StringComparison.OrdinalIgnoreCase)
                        ? "[ERR]"
                        : normalized.StartsWith("[", StringComparison.Ordinal)
                            ? ""
                            : "[INFO]";

        string clean = normalized
            .TrimStart('✓', '!', ' ')
            .Replace("\r", " ")
            .Replace("\n", " ");

        string line = $"{DateTime.Now:HH:mm:ss}   {tag,-6} {clean}";
        _activityLines.Add(line);

        if (_activityLines.Count > 250)
            _activityLines.RemoveAt(0);

        if (_activityBox.IsHandleCreated)
        {
            AppendColoredActivityLine(line);
            _activityBox.SelectionStart = _activityBox.TextLength;
            _activityBox.ScrollToCaret();
        }

        UpdateGuidedCheck(line);
        ParseArtifactCount(clean);
        AdvanceScanForMessage(clean);
    }

    private void AppendColoredActivityLine(string line)
    {
        int tagStart = line.IndexOf('[');
        int tagEnd =
            tagStart >= 0
                ? line.IndexOf(']', tagStart + 1)
                : -1;

        int timestampEnd = Math.Min(11, line.Length);

        _activityBox.SelectionColor = Color.FromArgb(159, 191, 232);
        _activityBox.AppendText(line[..timestampEnd]);

        if (tagStart >= timestampEnd && tagEnd > tagStart)
        {
            if (tagStart > timestampEnd)
            {
                _activityBox.SelectionColor = Color.FromArgb(180, 205, 238);
                _activityBox.AppendText(line[timestampEnd..tagStart]);
            }

            string tag = line[tagStart..(tagEnd + 1)];
            _activityBox.SelectionColor = ActivityTagColor(tag);
            _activityBox.AppendText((tag.Contains("OK") ? "✓   " : tag.Contains("ERR") ? "×   " : tag.Contains("WARN") ? "!   " : "i   ") + tag);

            if (tagEnd + 1 < line.Length)
            {
                _activityBox.SelectionColor = Color.FromArgb(180, 205, 238);
                _activityBox.AppendText(line[(tagEnd + 1)..]);
            }
        }
        else if (timestampEnd < line.Length)
        {
            _activityBox.SelectionColor = Color.FromArgb(180, 205, 238);
            _activityBox.AppendText(line[timestampEnd..]);
        }

        _activityBox.SelectionColor = Color.FromArgb(180, 205, 238);
        _activityBox.AppendText(Environment.NewLine);
    }

    private static Color ActivityTagColor(string tag)
    {
        string normalized = tag.Trim().ToUpperInvariant();

        if (normalized.Contains("ERR"))
            return Danger;

        if (normalized.Contains("WARN"))
            return Warning;

        if (normalized.Contains("OK"))
            return Success;

        if (normalized.Contains("INIT") ||
            normalized.Contains("INFO"))
            return Blue;

        return TextSecondary;
    }

    private void ParseArtifactCount(string message)
    {
        int colon = message.LastIndexOf(':');
        if (colon < 0 || colon == message.Length - 1)
            return;

        string tail = message[(colon + 1)..].Trim();
        if (!int.TryParse(tail, out int count) || count < 0)
            return;

        _artifactCount += count;
        _artifactCountLabel.Text = $"{_artifactCount:N0} itens";

        if (message.Contains("USB", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("seriais", StringComparison.OrdinalIgnoreCase))
        {
            _devicesSeen += count;
            _deviceCountLabel.Text = $"{_devicesSeen} dispositivos";
        }
    }

    private void AdvanceScanForMessage(string message)
    {
        int stage = 0;
        int minimum = 5;
        string lower = message.ToLowerInvariant();

        if (lower.Contains("integridade") || lower.Contains("processos") || lower.Contains("drivers"))
        {
            stage = 1;
            minimum = 18;
        }

        if (lower.Contains("prefetch") || lower.Contains("bam") || lower.Contains("amcache") ||
            lower.Contains("shimcache") || lower.Contains("execução"))
        {
            stage = 2;
            minimum = 32;
        }

        if (lower.Contains("usb") || lower.Contains("serial"))
        {
            stage = 3;
            minimum = 48;
        }

        if (lower.Contains("download") || lower.Contains("navegador") || lower.Contains("zone") ||
            lower.Contains("origem"))
        {
            stage = 4;
            minimum = 58;
        }

        if (lower.Contains("módulo") || lower.Contains("serviço") || lower.Contains("memória"))
        {
            stage = 5;
            minimum = 68;
        }

        if (lower.Contains("correl") || lower.Contains("filtro") ||
            lower.Contains("revis") || lower.Contains("processando"))
        {
            stage = 6;
            minimum = 80;
        }

        if (lower.Contains("relatório") || lower.Contains("enviando") || lower.Contains("dados enviados"))
        {
            stage = 7;
            minimum = 92;
        }

        _progressPercent = Math.Max(_progressPercent, minimum);
        UpdateStageStates(stage);
        UpdateProgressUi();

        if (!string.IsNullOrWhiteSpace(message))
            _progressEtaLabel.Text = Ellipsize(message, 90);
    }

    private void UpdateStageStates(int activeStage)
    {
        for (int i = 0; i < _stepStateLabels.Count; i++)
        {
            Label label = _stepStateLabels[i];

            if (i < activeStage)
            {
                label.Text = "●  OK";
                label.ForeColor = Accent;
            }
            else if (i == activeStage && _running)
            {
                label.Text = "◌  ANALISANDO";
                label.ForeColor = TextPrimary;
            }
            else
            {
                label.Text = "○  PENDENTE";
                label.ForeColor = TextDim;
            }
        }
    }

    private void UpdateProgressUi()
    {
        int width = Math.Max(4, (int)(_progressTrack.Width * (_progressPercent / 100d)));
        _progressFill.Width = Math.Min(_progressTrack.Width, width);
        _progressPercentLabel.Text = $"{_progressPercent}%";
    }

    private async void ClientResultPollTimer_Tick(object? sender, EventArgs e)
    {
        if (_running || _lastRun is null)
            return;

        try
        {
            AgentResultSnapshot? refreshed =
                await Program.FetchCurrentResultAsync(_args);

            if (refreshed is null)
                return;

            bool releaseChanged =
                _lastRun.Result?.DetailsReleased !=
                refreshed.DetailsReleased;

            int previousFindingCount =
                _lastRun.Result?.Findings?.Count ?? 0;

            _lastRun.Result = refreshed;

            if (releaseChanged ||
                previousFindingCount != refreshed.Findings.Count)
            {
                ShowResultsView(_lastRun);
            }
        }
        catch
        {
            // A liberação é opcional. Falhas temporárias de rede não alteram o relatório local.
        }
    }

    private void ShowDetailedResultsView(AgentRunResult result)
    {
        if (InvokeRequired)
        {
            BeginInvoke((Action)(() => ShowResultsView(result)));
            return;
        }

        _surface.Controls.Clear();
        _surface.Mode = result.ExitCode == 0
            ? AnimatedSurfaceMode.Complete
            : AnimatedSurfaceMode.Error;
        _nav.Visible = true;
        SetActiveNav(2);

        bool success = result.ExitCode == 0;
        AgentResultSnapshot? snapshot = result.Result;

        int criticalCount = snapshot?.Summary.Critical ?? 0;
        int reviewCount = snapshot?.Summary.Review ?? 0;
        int inventoryCount = snapshot?.Summary.Inventory ?? Math.Max(_artifactCount, 0);
        int detectionCount = criticalCount + reviewCount;
        bool hasCritical = criticalCount > 0;
        bool hasReview = !hasCritical && reviewCount > 0;
        bool filterError =
            string.Equals(snapshot?.VerificationState, "error", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(snapshot?.ProcessingStage, "filter_error", StringComparison.OrdinalIgnoreCase);
        bool autoApproved =
            !filterError &&
            (
                string.Equals(snapshot?.VerificationState, "approved", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(snapshot?.ExternalDecision, "approve", StringComparison.OrdinalIgnoreCase)
            );
        bool detailsReleased = snapshot?.DetailsReleased == true;

        string resultHeadline =
            !success
                ? L("Análise interrompida.", "Análisis interrumpido.", "Analysis interrupted.")
                : filterError
                    ? L("Falha parcial nos filtros.", "Fallo parcial en los filtros.", "Partial filter failure.")
                    : hasCritical
                        ? L("Possível trapaceiro detectado.", "Posible tramposo detectado.", "Possible cheater detected.")
                        : hasReview
                            ? L("Atividades incomuns localizadas.", "Actividades inusuales encontradas.", "Unusual activity found.")
                            : autoApproved
                                ? L("Verificação aprovada.", "Verificación aprobada.", "Verification approved.")
                                : L("Análise limpa.", "Análisis limpio.", "Clean analysis.");

        string resultSubheadline =
            !success
                ? L("Não foi possível concluir.", "No fue posible finalizar.", "Could not complete.")
                : filterError
                    ? L("Aguarde a verificação administrativa.", "Espere la verificación administrativa.", "Wait for administrative verification.")
                    : hasCritical
                        ? L("Aguarde a análise administrativa.", "Espere el análisis administrativo.", "Wait for administrative review.")
                        : hasReview
                            ? L("Revisão necessária.", "Revisión necesaria.", "Review required.")
                            : autoApproved
                                ? L("Liberação automática concluída.", "Aprobación automática completada.", "Automatic approval completed.")
                                : L("Nenhum item suspeito encontrado.", "No se encontraron elementos sospechosos.", "No suspicious items found.");

        Color resultAccent =
            filterError
                ? Warning
                : hasCritical
                    ? Danger
                    : hasReview
                        ? Warning
                        : Accent;

        _visibleFindings.Clear();
        if (detailsReleased && snapshot?.Findings is not null)
            _visibleFindings.AddRange(snapshot.Findings);

        if (success)
            _clientResultPollTimer.Start();
        else
            _clientResultPollTimer.Stop();

        var badge = MakeBadge(L("RESULTADOS   ·   RELATÓRIO DE ANÁLISE", "RESULTADOS   ·   INFORME DE ANÁLISIS", "RESULTS   ·   ANALYSIS REPORT"));
        badge.Location = new Point(44, 24);
        _surface.Controls.Add(badge);

        _surface.Controls.Add(MakeLabel(
            resultHeadline,
            new Rectangle(44, 70, 720, 58),
            24F,
            TextPrimary,
            FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            resultSubheadline,
            new Rectangle(44, 119, 720, 44),
            14F,
            success ? resultAccent : Danger,
            FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            success
                ? detailsReleased
                    ? "O relatório detalhado foi liberado pela administração.\nAs evidências abaixo estão disponíveis para revisão."
                    : filterError
                        ? "A classificação não terminou corretamente.\nEsta análise não será liberada automaticamente; aguarde a administração."
                        : hasCritical
                            ? "Foi encontrada evidência crítica em vermelho.\nPossível trapaceiro detectado; aguarde a análise administrativa."
                            : hasReview
                                ? "Foram localizadas atividades incomuns em laranja.\nÉ necessária revisão administrativa antes da conclusão."
                                : autoApproved
                                    ? "Nenhum item vermelho ou laranja foi encontrado.\nSua verificação foi aprovada automaticamente."
                                    : "Nenhum item vermelho ou laranja foi encontrado."
                : "A coleta foi interrompida antes da conclusão.",
            new Rectangle(46, 180, 610, 58),
            10.4F,
            TextSecondary));

        var statusCard = MakeCard(new Rectangle(800, 38, 426, 182));
        statusCard.Controls.Add(MakeLabel(
            L("STATUS DA ANÁLISE", "ESTADO DEL ANÁLISIS", "ANALYSIS STATUS"),
            new Rectangle(22, 18, 210, 22),
            8.4F,
            Accent,
            FontStyle.Bold,
            "Consolas"));
        statusCard.Controls.Add(MakeLabel(
            success ? (filterError ? "!" : hasCritical ? "⚠" : hasReview ? "!" : "✓") : "!",
            new Rectangle(26, 55, 58, 58),
            30F,
            success ? resultAccent : Danger,
            FontStyle.Bold));
        statusCard.Controls.Add(MakeLabel(
            success
                ? (filterError ? "REVISAR" : hasCritical ? "CRÍTICO" : hasReview ? "REVISAR" : autoApproved ? "VERIFICADO" : "LIMPO")
                : "ERRO",
            new Rectangle(96, 61, 190, 36),
            16F,
            success ? resultAccent : Danger,
            FontStyle.Bold));
        statusCard.Controls.Add(MakeLabel(
            L("Duração da análise: ", "Duración del análisis: ", "Analysis duration: ") + FormatDuration(DateTime.Now - _scanStartedAt) + "\n" +
            L("Concluído em: ", "Completado: ", "Completed: ") + $"{DateTime.Now:dd/MM/yyyy HH:mm}",
            new Rectangle(96, 108, 240, 52),
            8.8F,
            TextSecondary));

        _surface.Controls.Add(statusCard);

        if (detailsReleased)
        {
            var criticalCard = MakeFindingColumn(
                "⚠", "CRÍTICO", criticalCount, "Achados de alta severidade",
                Danger, new Rectangle(28, 258, 380, 292),
                _visibleFindings.Where(x => x.Severity == "critical").ToList());

            var reviewCard = MakeFindingColumn(
                "!", "REVISAR", reviewCount, "Itens suspeitos · alto/médio",
                Warning, new Rectangle(420, 258, 380, 292),
                _visibleFindings.Where(x => x.Severity is "high" or "medium").ToList());

            var inventoryCard = MakeInventoryColumn(
                inventoryCount,
                new Rectangle(812, 258, 414, 292));

            _surface.Controls.Add(criticalCard);
            _surface.Controls.Add(reviewCard);
            _surface.Controls.Add(inventoryCard);
        }
        else
        {
            var lockedCard = MakeCard(new Rectangle(28, 258, 1198, 292));
            lockedCard.BorderColor = !success ? Danger : filterError ? Warning : hasCritical ? Danger : hasReview ? Warning : Accent;

            lockedCard.Controls.Add(MakeLabel(
                !success ? "!" : filterError ? "!" : hasCritical ? "⚠" : hasReview ? "!" : "✓",
                new Rectangle(30, 44, 80, 80),
                36F,
                !success ? Danger : filterError ? Warning : hasCritical ? Danger : hasReview ? Warning : Accent,
                FontStyle.Bold));

            lockedCard.Controls.Add(MakeLabel(
                !success
                    ? "Análise interrompida"
                    : filterError
                    ? "Falha parcial nos filtros"
                    : hasCritical
                        ? "Possível trapaceiro detectado"
                        : hasReview
                            ? "Atividades incomuns localizadas"
                            : autoApproved
                                ? "Verificação aprovada automaticamente"
                                : "Nenhum item suspeito",
                new Rectangle(130, 46, 650, 42),
                23F,
                TextPrimary,
                FontStyle.Bold));

            lockedCard.Controls.Add(MakeLabel(
                !success
                    ? "A verificação não foi concluída. Consulte os registros e tente novamente com seu consentimento."
                    : filterError
                    ? "Os filtros não terminaram corretamente. Esta análise não é considerada limpa e exige revisão administrativa."
                    : hasCritical
                        ? $"Foi registrado {criticalCount} item crítico em vermelho. " +
                          "Aguarde a análise administrativa antes da conclusão da verificação."
                        : hasReview
                            ? $"Foram localizadas {reviewCount} atividade(s) incomum(ns) em laranja. " +
                              "É necessária revisão administrativa."
                            : autoApproved
                                ? "Nenhum item vermelho ou laranja foi encontrado. A liberação automática foi confirmada."
                                : "Nenhum item vermelho ou laranja foi encontrado nesta análise.",
                new Rectangle(132, 98, 930, 56),
                10F,
                TextSecondary));

            lockedCard.Controls.Add(MakeLabel(
                "DETALHES RESTRITOS",
                new Rectangle(132, 176, 240, 24),
                8F,
                Warning,
                FontStyle.Bold,
                "Consolas"));

            lockedCard.Controls.Add(MakeLabel(
                "Se a administração liberar o relatório, os detalhes aparecerão automaticamente nesta tela.",
                new Rectangle(132, 204, 820, 30),
                8.8F,
                TextDim));

            _surface.Controls.Add(lockedCard);
        }

        var summaryCard = MakeCard(new Rectangle(28, 565, 590, 230));
        summaryCard.Controls.Add(MakeSectionTitle("●   RESUMO DA ANÁLISE", 18, 16));
        if (detailsReleased)
        {
            summaryCard.Controls.Add(MakeSummaryMetric("⚠", criticalCount.ToString(), "Itens críticos", "Vermelho · prioridade máxima", Danger, 18));
            summaryCard.Controls.Add(MakeSummaryMetric("!", reviewCount.ToString(), "Itens para revisão", "Laranja · suspeitos", Warning, 196));
            summaryCard.Controls.Add(MakeSummaryMetric("▤", inventoryCount.ToString(), "Artefatos catalogados", "Inventário técnico", Blue, 388));
        }
        else
        {
            int restrictedResultCount =
                hasCritical
                    ? criticalCount
                    : hasReview
                        ? reviewCount
                        : 0;

            summaryCard.Controls.Add(MakeSummaryMetric(
                restrictedResultCount > 0 ? "!" : "✓",
                restrictedResultCount.ToString(),
                hasCritical
                    ? (criticalCount == 1 ? "Detecção crítica" : "Detecções críticas")
                    : hasReview
                        ? "Atividades para revisão"
                        : "Detecções registradas",
                hasCritical
                    ? "Somente itens vermelhos"
                    : hasReview
                        ? "Laranja · revisão necessária"
                        : "Detalhes restritos",
                hasCritical ? Danger : hasReview ? Warning : Accent,
                18));
        }

        string sessionId = snapshot?.AnalysisId > 0 ? snapshot.AnalysisId.ToString() : "—";
        summaryCard.Controls.Add(MakeLabel(
            $"ID da sessão                 {sessionId}\n" +
            $"Data e hora                   {DateTime.Now:dd/MM/yyyy HH:mm:ss}\n" +
            $"Duração                       {FormatDuration(DateTime.Now - _scanStartedAt)}\n" +
            "Modo de varredura              Sob demanda (User Mode)",
            new Rectangle(18, 126, 548, 88),
            8.3F,
            TextSecondary,
            FontStyle.Regular,
            "Consolas"));
        _surface.Controls.Add(summaryCard);

        _evidenceDetailPanel = MakeCard(new Rectangle(630, 565, 596, 230));
        _evidenceDetailPanel.Controls.Add(MakeSectionTitle(
            detailsReleased ? "DETALHES DA EVIDÊNCIA" : "ACESSO AO RELATÓRIO",
            18,
            15));
        _surface.Controls.Add(_evidenceDetailPanel);

        if (detailsReleased)
        {
            AgentFindingSnapshot? selected =
                _visibleFindings.FirstOrDefault(x => x.Severity == "critical")
                ?? _visibleFindings.FirstOrDefault(x => x.Severity is "high" or "medium")
                ?? _visibleFindings.FirstOrDefault();

            ShowEvidenceDetail(selected);
        }
        else
        {
            var restricted = MakeLabel(
                filterError
                    ? "Falha parcial nos filtros.\n\nEsta análise exige revisão administrativa e não será liberada automaticamente."
                    : hasCritical
                        ? "Possível trapaceiro detectado.\n\n" +
                          "A administração recebeu a evidência crítica. Aguarde a análise administrativa."
                        : hasReview
                            ? "Atividades incomuns foram localizadas.\n\n" +
                              "A administração recebeu os achados em laranja. Revisão necessária."
                            : autoApproved
                                ? "Verificação aprovada automaticamente.\n\n" +
                                  "Nenhum item vermelho ou laranja foi encontrado."
                                : "A análise foi concluída sem itens críticos ou suspeitos.",
                new Rectangle(20, 62, 540, 116),
                9.4F,
                TextSecondary);
            restricted.Tag = "dynamic";
            _evidenceDetailPanel.Controls.Add(restricted);
        }

        SetHeaderState(
            success
                ? (filterError ? "REVISAR" : hasCritical ? "CRÍTICO" : hasReview ? "REVISAR" : autoApproved ? "VERIFICADO" : "LIMPO")
                : "ERRO",
            success ? resultAccent : Danger);
    }

    private VorkenCard MakeFindingColumn(
        string icon,
        string title,
        int count,
        string subtitle,
        Color color,
        Rectangle bounds,
        List<AgentFindingSnapshot> items)
    {
        var card = MakeCard(bounds);
        card.BorderColor = color;
        card.AutoScroll = true;

        card.Controls.Add(MakeLabel(icon, new Rectangle(18, 18, 42, 42), 21F, color, FontStyle.Bold));
        card.Controls.Add(MakeLabel(title, new Rectangle(67, 17, 160, 26), 13.5F, color, FontStyle.Bold));
        var countBadge = new Label
        {
            Text = count.ToString(),
            Bounds = new Rectangle(230, 17, 36, 24),
            BackColor = Color.FromArgb(45, color),
            ForeColor = color,
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleCenter
        };
        AttachRoundedRegion(countBadge, 7);
        card.Controls.Add(countBadge);
        card.Controls.Add(MakeLabel(subtitle, new Rectangle(67, 44, 260, 20), 8.5F, TextSecondary));

        int y = 78;
        if (items.Count == 0)
        {
            card.Controls.Add(MakeLabel(
                "Nenhum item nesta categoria.",
                new Rectangle(22, y + 18, 320, 24),
                9F,
                TextDim));
            return card;
        }

        foreach (AgentFindingSnapshot finding in items)
        {
            var row = new Button
            {
                Text = BuildFindingRowText(finding),
                Bounds = new Rectangle(14, y, bounds.Width - 32, 48),
                TextAlign = ContentAlignment.MiddleLeft,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(8, 18, 24),
                ForeColor = TextPrimary,
                Font = new Font("Segoe UI", 10.5F),
                Cursor = Cursors.Hand
            };
            row.FlatAppearance.BorderColor = color;
            row.FlatAppearance.BorderSize = 1;
            AttachRoundedRegion(row, 8);
            row.Click += (_, _) => ShowEvidenceDetail(finding);
            card.Controls.Add(row);
            y += 54;
        }

        return card;
    }

    private VorkenCard MakeInventoryColumn(int count, Rectangle bounds)
    {
        var card = MakeCard(bounds);
        card.BorderColor = Blue;
        card.Controls.Add(MakeLabel("▤", new Rectangle(18, 18, 42, 42), 20F, Blue, FontStyle.Bold));
        card.Controls.Add(MakeLabel("INVENTÁRIO", new Rectangle(67, 17, 180, 26), 13.5F, Blue, FontStyle.Bold));
        var inventoryBadge = new Label
        {
            Text = count.ToString(),
            Bounds = new Rectangle(246, 17, 42, 24),
            BackColor = Color.FromArgb(25, 55, 100),
            ForeColor = Blue,
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleCenter
        };
        AttachRoundedRegion(inventoryBadge, 7);
        card.Controls.Add(inventoryBadge);
        card.Controls.Add(MakeLabel(
            "Artefatos catalogados (baixo risco)",
            new Rectangle(67, 44, 290, 20),
            8.5F,
            TextSecondary));

        string[] rows =
        {
            "↕  Dispositivos e hardware|USB, drivers e dispositivos conectados",
            "▣  Aplicações instaladas|Programas e versões identificadas",
            "⚙  Serviços e processos|Serviços em execução no sistema",
            "⌘  Rede e conexões|Conexões recentes e endpoints"
        };

        int y = 82;
        foreach (string line in rows)
        {
            string[] parts = line.Split('|');
            card.Controls.Add(MakeLabel(parts[0], new Rectangle(20, y, 330, 22), 9.3F, TextPrimary));
            card.Controls.Add(MakeLabel(parts[1], new Rectangle(44, y + 23, 325, 18), 7.5F, TextDim));
            y += 49;
        }

        return card;
    }

    private Control MakeSummaryMetric(
        string icon,
        string number,
        string title,
        string subtitle,
        Color color,
        int x)
    {
        var panel = new Panel
        {
            Bounds = new Rectangle(x, 48, 170, 70),
            BackColor = Color.Transparent
        };
        panel.Controls.Add(MakeLabel(icon, new Rectangle(0, 8, 42, 42), 20F, color, FontStyle.Bold));
        panel.Controls.Add(MakeLabel(number, new Rectangle(48, 3, 60, 30), 17F, color, FontStyle.Bold));
        panel.Controls.Add(MakeLabel(title, new Rectangle(48, 32, 116, 19), 8.4F, TextPrimary));
        panel.Controls.Add(MakeLabel(subtitle, new Rectangle(48, 50, 122, 18), 7.2F, color));
        return panel;
    }

    private void ShowEvidenceDetail(AgentFindingSnapshot? finding)
    {
        if (_evidenceDetailPanel is null)
            return;

        foreach (Control control in _evidenceDetailPanel.Controls.Cast<Control>().ToList())
        {
            if (control.Tag?.ToString() == "dynamic")
                _evidenceDetailPanel.Controls.Remove(control);
        }

        if (finding is null)
        {
            var empty = MakeLabel(
                "Nenhuma evidência crítica selecionada.\nO relatório foi concluído e enviado para revisão.",
                new Rectangle(20, 62, 540, 58),
                9.4F,
                TextSecondary);
            empty.Tag = "dynamic";
            _evidenceDetailPanel.Controls.Add(empty);
            return;
        }

        Color color = finding.Severity == "critical" ? Danger : Warning;

        var severity = new Label
        {
            Text = SeverityLabel(finding.Severity),
            Bounds = new Rectangle(445, 12, 126, 26),
            BackColor = Color.FromArgb(35, color),
            ForeColor = color,
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleCenter,
            Tag = "dynamic"
        };
        AttachRoundedRegion(severity, 7);

        var title = MakeLabel(
            finding.Title,
            new Rectangle(72, 54, 450, 26),
            11.2F,
            TextPrimary,
            FontStyle.Bold);
        title.Tag = "dynamic";

        var icon = new Label
        {
            Text = "▤",
            Bounds = new Rectangle(20, 50, 42, 42),
            BackColor = Color.FromArgb(45, color),
            ForeColor = color,
            Font = new Font("Segoe UI Symbol", 17F, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleCenter,
            Tag = "dynamic"
        };
        AttachRoundedRegion(icon, 9);

        string artifact = finding.ArtifactValue ?? "—";
        string evidenceText = FriendlyEvidence(finding.Evidence);

        var body = MakeLabel(
            $"Artefato\n{artifact}\n\nJustificativa\n{evidenceText}",
            new Rectangle(20, 98, 548, 114),
            8.1F,
            TextSecondary);
        body.Tag = "dynamic";

        _evidenceDetailPanel.Controls.Add(severity);
        _evidenceDetailPanel.Controls.Add(icon);
        _evidenceDetailPanel.Controls.Add(title);
        _evidenceDetailPanel.Controls.Add(body);
    }

    private static string FriendlyEvidence(JsonElement evidence)
    {
        if (evidence.ValueKind != JsonValueKind.Object)
            return "Evidência técnica registrada para revisão.";

        foreach (string property in new[] { "note", "reason", "description", "source", "path" })
        {
            if (evidence.TryGetProperty(property, out JsonElement value) &&
                value.ValueKind == JsonValueKind.String &&
                !string.IsNullOrWhiteSpace(value.GetString()))
            {
                return Ellipsize(value.GetString()!, 210);
            }
        }

        string raw = evidence.ToString();
        return string.IsNullOrWhiteSpace(raw)
            ? "Evidência técnica registrada para revisão."
            : Ellipsize(raw, 210);
    }

    private void ShowCompletionHome()
    {
        if (_lastRun is null)
        {
            ShowConsentView();
            return;
        }

        ShowResultsView(_lastRun);
        SetActiveNav(0);
    }

    private void ShowAnalysisSummaryView()
    {
        if (_lastRun is null) { ShowConsentView(); SetActiveNav(1); return; }
        ShowResultsView(_lastRun); SetActiveNav(1);
    }

    private void ShowHistoryView()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Idle;
        _nav.Visible = true;
        SetActiveNav(3);

        var historyBadge = MakeBadge("HISTÓRICO   ·   SESSÕES LOCAIS");
        historyBadge.Location = new Point(44, 34);
        _surface.Controls.Add(historyBadge);
        _surface.Controls.Add(MakeLabel(
            "Histórico de análises",
            new Rectangle(44, 80, 700, 56),
            31F,
            TextPrimary,
            FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            "Sessões realizadas nesta execução do Vorken.",
            new Rectangle(47, 137, 650, 24),
            10F,
            TextSecondary));

        var card = MakeCard(new Rectangle(44, 190, 1180, 220));
        card.Controls.Add(MakeSectionTitle("RELATÓRIO DA SESSÃO", 20, 18));

        if (_lastRun?.Result is AgentResultSnapshot result)
        {
            card.Controls.Add(MakeLabel(
                $"#{result.AnalysisId}   {result.Label}\n" +
                $"{DateTime.Now:dd/MM/yyyy HH:mm}   ·   {result.Status.ToUpperInvariant()}\n\n" +
                $"Críticos: {result.Summary.Critical}     Revisar: {result.Summary.Review}     Inventário: {result.Summary.Inventory}",
                new Rectangle(24, 58, 760, 120),
                11F,
                TextPrimary));
            var open = new GuidedActionButton
            {
                Text = "Abrir relatório  →",
                Bounds = new Rectangle(920, 78, 210, 48)
            };
            StylePrimaryButton(open);
            open.Click += (_, _) => ShowResultsView(_lastRun);
            card.Controls.Add(open);
        }
        else
        {
            card.Controls.Add(MakeLabel(
                "Nenhuma sessão concluída nesta execução.",
                new Rectangle(24, 70, 620, 28),
                10F,
                TextDim));
        }

        _surface.Controls.Add(card);
        SetHeaderState("READY", Accent);
    }

    private void ShowManualAnalysisView()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Idle;
        _nav.Visible = true;
        SetActiveNav(4);

        var badge = MakeBadge("ANÁLISE MANUAL   ·   FERRAMENTAS FORENSES");
        badge.Location = new Point(44, 28);
        _surface.Controls.Add(badge);

        _surface.Controls.Add(MakeLabel(
            "Ferramentas manuais",
            new Rectangle(44, 76, 680, 52),
            30F,
            TextPrimary,
            FontStyle.Bold));

        _surface.Controls.Add(MakeLabel(
            "Ferramentas oficiais listadas pela detect.ac. Clique em baixar para o Vorken obter a versão atual e executá-la automaticamente.",
            new Rectangle(47, 130, 1080, 42),
            9.8F,
            TextSecondary));

        var notice = new BorderedPanel
        {
            Bounds = new Rectangle(44, 178, 1180, 58),
            BackColor = Color.FromArgb(12, 29, 47),
            BorderColor = Color.FromArgb(40, 69, 105),
            CornerRadius = 10
        };

        notice.Controls.Add(MakeLabel(
            "◆",
            new Rectangle(16, 14, 28, 26),
            14F,
            Accent,
            FontStyle.Bold));

        notice.Controls.Add(MakeLabel(
            "Downloads são feitos somente por HTTPS a partir do endpoint oficial da detect.ac e seus redirecionamentos oficiais do GitHub.",
            new Rectangle(52, 12, 1085, 34),
            8.3F,
            TextSecondary));

        _surface.Controls.Add(notice);

        var toolsHost = new GuidedScrollHost { Bounds = new Rectangle(44, 252, 1180, 550), Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
        foreach (ManualToolDefinition tool in ManualTools) toolsHost.Content.Controls.Add(MakeManualToolCard(tool));
        _surface.Controls.Add(toolsHost);
        SetHeaderState("MANUAL", Accent);
    }

    private Control MakeManualToolCard(ManualToolDefinition tool)
    {
        var card = new VorkenCard
        {
            Size = new Size(558, 118),
            Margin = new Padding(0, 0, 14, 14),
            BackColor = Color.FromArgb(16, 29, 49),
            BorderColor = Border
        };

        var name = MakeLabel(
            tool.Name,
            new Rectangle(18, 14, 320, 26),
            11F,
            TextPrimary,
            FontStyle.Bold);

        var description = MakeLabel(
            tool.Description,
            new Rectangle(18, 42, 348, 42),
            8F,
            TextSecondary);

        var source = MakeLabel(
            "detect.ac  ·  download oficial",
            new Rectangle(18, 88, 300, 18),
            7F,
            AccentSoft,
            FontStyle.Bold,
            "Consolas");

        var status = MakeLabel(
            "Pronto",
            new Rectangle(385, 18, 150, 18),
            7.1F,
            TextDim,
            FontStyle.Bold,
            "Consolas");
        status.TextAlign = ContentAlignment.MiddleRight;

        var downloadButton = new GuidedActionButton
        {
            Text = "⇩  Baixar e executar",
            Bounds = new Rectangle(380, 51, 158, 42)
        };
        StylePrimaryButton(downloadButton);
        downloadButton.Font = new Font("Segoe UI", 8.5F, FontStyle.Bold);

        downloadButton.Click += async (_, _) =>
            await DownloadAndRunManualToolAsync(
                tool,
                downloadButton,
                status);

        card.Controls.Add(name);
        card.Controls.Add(description);
        card.Controls.Add(source);
        card.Controls.Add(status);
        card.Controls.Add(downloadButton);

        return card;
    }

    private async Task DownloadAndRunManualToolAsync(
        ManualToolDefinition tool,
        Button button,
        Label status)
    {
        if (!button.Enabled)
            return;

        button.Enabled = false;
        string originalText = button.Text;

        try
        {
            status.Text = "Conectando...";
            status.ForeColor = AccentSoft;
            button.Text = "Baixando...";

            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 10
            };

            using var http = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMinutes(4)
            };

            http.DefaultRequestHeaders.UserAgent.ParseAdd(
                "Vorken-AntiCheat/1.0.7");

            using HttpResponseMessage response =
                await http.GetAsync(
                    tool.DownloadUrl,
                    HttpCompletionOption.ResponseHeadersRead);

            response.EnsureSuccessStatusCode();

            Uri? finalUri =
                response.RequestMessage?.RequestUri;

            if (finalUri is null ||
                !string.Equals(
                    finalUri.Scheme,
                    Uri.UriSchemeHttps,
                    StringComparison.OrdinalIgnoreCase) ||
                !IsTrustedManualToolHost(finalUri.Host))
            {
                throw new InvalidOperationException(
                    "O download foi redirecionado para uma origem não autorizada.");
            }

            long? contentLength =
                response.Content.Headers.ContentLength;

            const long maxDownloadBytes =
                300L * 1024L * 1024L;

            if (contentLength.HasValue &&
                contentLength.Value > maxDownloadBytes)
            {
                throw new InvalidOperationException(
                    "O arquivo excede o limite de 300 MB.");
            }

            string downloadRoot =
                Path.Combine(
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.LocalApplicationData),
                    "Vorken",
                    "ManualTools");

            Directory.CreateDirectory(downloadRoot);

            string? headerName =
                response.Content.Headers.ContentDisposition?.FileNameStar ??
                response.Content.Headers.ContentDisposition?.FileName;

            string fileName =
                SanitizeManualToolFileName(
                    headerName,
                    tool.Name);

            string destination =
                Path.Combine(
                    downloadRoot,
                    fileName);

            await using (
                var file =
                    new FileStream(
                        destination,
                        FileMode.Create,
                        FileAccess.Write,
                        FileShare.Read))
            {
                await response.Content.CopyToAsync(file);
            }

            var info = new FileInfo(destination);

            if (!info.Exists ||
                info.Length <= 0 ||
                info.Length > maxDownloadBytes)
            {
                throw new InvalidOperationException(
                    "O arquivo baixado é inválido.");
            }

            if (!LooksLikePortableExecutable(destination))
            {
                throw new InvalidOperationException(
                    "O arquivo recebido não é um executável Windows válido.");
            }

            status.Text = "Executando...";
            status.ForeColor = Accent;
            button.Text = "Abrindo...";

            Process.Start(
                new ProcessStartInfo(destination)
                {
                    UseShellExecute = true,
                    WorkingDirectory = downloadRoot
                });

            status.Text = "Executado ✓";
            status.ForeColor = Success;
        }
        catch (Exception ex)
        {
            status.Text = "Falhou";
            status.ForeColor = Danger;

            MessageBox.Show(
                this,
                $"Não foi possível baixar/executar {tool.Name}.\n\n{ex.Message}",
                "Vorken · Análise Manual",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
        finally
        {
            button.Text = originalText;
            button.Enabled = true;
        }
    }

    private static bool IsTrustedManualToolHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return false;

        host = host.Trim().ToLowerInvariant();

        return host == "detect.ac" ||
               host.EndsWith(".detect.ac", StringComparison.Ordinal) ||
               host == "github.com" ||
               host.EndsWith(".github.com", StringComparison.Ordinal) ||
               host == "githubusercontent.com" ||
               host.EndsWith(".githubusercontent.com", StringComparison.Ordinal);
    }

    private static string SanitizeManualToolFileName(
        string? headerName,
        string toolName)
    {
        string candidate =
            string.IsNullOrWhiteSpace(headerName)
                ? toolName + ".exe"
                : headerName.Trim().Trim('"');

        foreach (char invalid in Path.GetInvalidFileNameChars())
            candidate = candidate.Replace(invalid, '_');

        if (!candidate.EndsWith(
                ".exe",
                StringComparison.OrdinalIgnoreCase))
        {
            candidate += ".exe";
        }

        return candidate;
    }

    private static bool LooksLikePortableExecutable(
        string path)
    {
        try
        {
            using var stream =
                File.OpenRead(path);

            if (stream.Length < 2)
                return false;

            return stream.ReadByte() == 'M' &&
                   stream.ReadByte() == 'Z';
        }
        catch
        {
            return false;
        }
    }

    private void ShowRemoteSupportView()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Idle;
        _nav.Visible = true;
        SetActiveNav(6);

        var badge = MakeBadge(L("SUPORTE REMOTO   ·   CONSENTIMENTO EM TEMPO REAL", "SOPORTE REMOTO   ·   CONSENTIMIENTO EN TIEMPO REAL", "REMOTE SUPPORT   ·   REAL-TIME CONSENT"));
        badge.Location = new Point(44, 32);
        _surface.Controls.Add(badge);
        _surface.Controls.Add(MakeLabel(
            L("Compartilhar esta tela com a administração", "Compartir esta pantalla con la administración", "Share this screen with the administration"),
            new Rectangle(44, 78, 880, 52), 28F, TextPrimary, FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            L(
                "Você escolhe quem poderá acessar, define o nível de permissão e pode encerrar imediatamente.",
                "Usted elige quién puede acceder, define el nivel de permiso y puede finalizar inmediatamente.",
                "You choose who may access, set the permission level and can stop it immediately."),
            new Rectangle(47, 132, 980, 28), 10.2F, TextSecondary));

        var setup = MakeCard(new Rectangle(44, 185, 770, 490));
        setup.Controls.Add(MakeSectionTitle(L("INICIAR UMA SESSÃO", "INICIAR UNA SESIÓN", "START A SESSION"), 22, 18));
        setup.Controls.Add(MakeLabel(L("Administrador disponível", "Administrador disponible", "Available administrator"), new Rectangle(24, 64, 360, 24), 9.5F, TextSecondary, FontStyle.Bold));

        var admins = new GuidedComboBox
        {
            Bounds = new Rectangle(24, 92, 470, 38),
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = SurfaceAlt,
            ForeColor = TextPrimary,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 10F)
        };
        setup.Controls.Add(admins);

        var refresh = new GuidedActionButton { Text = L("Atualizar", "Actualizar", "Refresh"), Bounds = new Rectangle(512, 91, 120, 42) };
        StyleGhostButton(refresh);
        setup.Controls.Add(refresh);

        var viewOnly = new RadioButton
        {
            Text = L("Somente visualizar a tela", "Solo visualizar la pantalla", "View screen only"),
            Bounds = new Rectangle(24, 164, 330, 34),
            Checked = true,
            ForeColor = TextPrimary,
            BackColor = Color.Transparent,
            Font = new Font("Segoe UI", 10.5F, FontStyle.Bold)
        };
        var control = new RadioButton
        {
            Text = L("Tela + controle de mouse e teclado", "Pantalla + control de ratón y teclado", "Screen + mouse and keyboard control"),
            Bounds = new Rectangle(24, 206, 420, 34),
            ForeColor = Warning,
            BackColor = Color.Transparent,
            Font = new Font("Segoe UI", 10.5F, FontStyle.Bold)
        };
        setup.Controls.Add(viewOnly);
        setup.Controls.Add(control);
        setup.Controls.Add(MakeLabel(
            L(
                "O modo de controle permite cliques e digitação enquanto a sessão estiver visível.\nNão inclui arquivos, área de transferência, senhas salvas ou acesso após o encerramento.",
                "El modo de control permite clics y escritura mientras la sesión esté visible.\nNo incluye archivos, portapapeles, contraseñas guardadas ni acceso posterior.",
                "Control mode allows clicking and typing while the session is visible.\nIt does not include files, clipboard, saved passwords or access after it ends."),
            new Rectangle(47, 246, 650, 58), 9.3F, TextSecondary));

        var consent = new CheckBox
        {
            Text = L("Eu entendo o nível selecionado e autorizo esta sessão.", "Entiendo el nivel seleccionado y autorizo esta sesión.", "I understand the selected access level and authorize this session."),
            Bounds = new Rectangle(24, 322, 620, 38),
            ForeColor = TextPrimary,
            BackColor = Color.Transparent,
            Font = new Font("Segoe UI", 9.8F)
        };
        setup.Controls.Add(consent);

        var start = new GuidedActionButton { Text = L("SOLICITAR CONEXÃO", "SOLICITAR CONEXIÓN", "REQUEST CONNECTION"), Bounds = new Rectangle(24, 385, 250, 48) };
        StylePrimaryButton(start);
        var stop = new GuidedActionButton { Text = L("PARAR AGORA", "DETENER AHORA", "STOP NOW"), Bounds = new Rectangle(290, 385, 190, 48), Enabled = _remoteSupport?.IsActive == true };
        StyleGhostButton(stop);
        stop.ForeColor = Danger;
        setup.Controls.Add(start);
        setup.Controls.Add(stop);

        _remoteStatusLabel = MakeLabel(
            _remoteSupport?.IsActive == true
                ? L("Sessão ativa.", "Sesión activa.", "Session active.")
                : L("Nenhuma transmissão ativa.", "No hay transmisión activa.", "No active screen sharing."),
            new Rectangle(24, 438, 714, 46), 10F,
            _remoteSupport?.IsActive == true ? Warning : TextDim, FontStyle.Bold);
        setup.Controls.Add(_remoteStatusLabel);
        _surface.Controls.Add(setup);

        var safety = MakeCard(new Rectangle(842, 185, 350, 330));
        safety.Controls.Add(MakeSectionTitle(L("PROTEÇÕES DA SESSÃO", "PROTECCIONES DE LA SESIÓN", "SESSION PROTECTIONS"), 20, 18));
        safety.Controls.Add(MakeLabel(
            L(
                "● Aceite dos dois lados\n\n● Indicador visível durante todo o acesso\n\n● Expiração automática\n\n● Interrupção imediata pelo jogador\n\n● Registro de início, aceite e término",
                "● Aceptación de ambas partes\n\n● Indicador visible durante el acceso\n\n● Expiración automática\n\n● Interrupción inmediata por el jugador\n\n● Registro de inicio, aceptación y final",
                "● Acceptance by both sides\n\n● Visible indicator throughout access\n\n● Automatic expiration\n\n● Immediate stop by the player\n\n● Start, acceptance and end log"),
            new Rectangle(24, 66, 300, 230), 10F, TextSecondary));
        _surface.Controls.Add(safety);

        async Task LoadAdminsAsync()
        {
            refresh.Enabled = false;
            try
            {
                await using var client = new RemoteSupportClient(Program.LoadConfig(_args));
                List<RemoteAdministrator> available = await client.GetAvailableAdminsAsync();
                admins.Items.Clear();
                foreach (RemoteAdministrator admin in available) admins.Items.Add(admin);
                if (admins.Items.Count > 0) admins.SelectedIndex = 0;
                UpdateRemoteStatus(available.Count == 0
                    ? "Nenhum administrador está disponível neste momento."
                    : $"{available.Count} administrador(es) disponível(is).", false);
            }
            catch (Exception ex)
            {
                UpdateRemoteStatus("Não foi possível consultar administradores: " + ex.Message, false);
            }
            finally { if (!refresh.IsDisposed) refresh.Enabled = true; }
        }

        refresh.Click += async (_, _) => await LoadAdminsAsync();
        stop.Click += async (_, _) => await StopRemoteSupportAsync();
        start.Click += async (_, _) =>
        {
            if (_remoteSupport?.IsActive == true) return;
            if (admins.SelectedItem is not RemoteAdministrator admin)
            {
                MessageBox.Show(this, "Selecione um administrador disponível.", "Suporte Vorken", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (!consent.Checked)
            {
                MessageBox.Show(this, "Marque o consentimento antes de solicitar a conexão.", "Suporte Vorken", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string mode = control.Checked ? "control" : "view";
            string permission = control.Checked ? "ver a tela e controlar mouse/teclado" : "somente ver a tela";
            if (MessageBox.Show(this,
                $"Autorizar {admin.DisplayName} a {permission}?\n\nVocê poderá parar a sessão pelo botão vermelho no topo do Vorken.",
                "Confirmar suporte remoto", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;

            start.Enabled = false;
            _remoteSupport = new RemoteSupportClient(Program.LoadConfig(_args));
            RemoteSupportClient runningClient = _remoteSupport;
            stop.Enabled = true;
            UpdateRemoteStatus("Preparando solicitação segura...", true);
            try
            {
                await runningClient.RunAsync(admin.Id, mode, message => UpdateRemoteStatus(message, runningClient.IsActive));
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                UpdateRemoteStatus("Sessão não iniciada: " + ex.Message, false);
            }
            finally
            {
                if (ReferenceEquals(_remoteSupport, runningClient))
                {
                    await runningClient.DisposeAsync();
                    _remoteSupport = null;
                }
                if (!start.IsDisposed) start.Enabled = true;
                if (!stop.IsDisposed) stop.Enabled = false;
                UpdateRemoteStatus("Transmissão encerrada.", false);
            }
        };

        _ = LoadAdminsAsync();
    }

    private void UpdateRemoteStatus(string message, bool active)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => UpdateRemoteStatus(message, active));
            return;
        }
        if (_remoteStatusLabel is { IsDisposed: false })
        {
            _remoteStatusLabel.Text = message;
            _remoteStatusLabel.ForeColor = active ? Warning : TextDim;
        }
        bool sessionOpen = active || _remoteSupport is not null;
        _headerStatus.Text = sessionOpen ? "■  PARAR SUPORTE" : "●  READY";
        _headerStatus.ForeColor = sessionOpen ? Color.White : Accent;
        _headerStatus.BackColor = sessionOpen ? Danger : Color.FromArgb(20, 40, 71);
        _headerStatus.Cursor = sessionOpen ? Cursors.Hand : Cursors.Default;
    }

    private async Task StopRemoteSupportAsync()
    {
        RemoteSupportClient? client = _remoteSupport;
        if (client is null) return;
        UpdateRemoteStatus("Encerrando transmissão...", false);
        await client.StopAsync();
    }

    private void ShowSettingsView()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Idle;
        _nav.Visible = true;
        SetActiveNav(5);

        var settingsBadge = MakeBadge(L("CONFIGURAÇÕES   ·   VORKEN", "CONFIGURACIÓN   ·   VORKEN", "SETTINGS   ·   VORKEN"));
        settingsBadge.Location = new Point(44, 34);
        _surface.Controls.Add(settingsBadge);
        _surface.Controls.Add(MakeLabel(
            L("Configurações", "Configuración", "Settings"),
            new Rectangle(44, 80, 600, 56),
            31F,
            TextPrimary,
            FontStyle.Bold));

        var card = MakeCard(new Rectangle(44, 180, 780, 405));
        card.Controls.Add(MakeSectionTitle(L("SESSÃO E PRIVACIDADE", "SESIÓN Y PRIVACIDAD", "SESSION AND PRIVACY"), 20, 20));
        card.Controls.Add(MakeLabel(
            L(
                "Modo de análise\nON DEMAND · USER MODE\n\nO scanner só executa após consentimento explícito.\nSenhas, cookies, mensagens, fotos e documentos pessoais não fazem parte da coleta.",
                "Modo de análisis\nON DEMAND · USER MODE\n\nEl escáner solo se ejecuta después del consentimiento explícito.\nContraseñas, cookies, mensajes, fotos y documentos personales no se recopilan.",
                "Analysis mode\nON DEMAND · USER MODE\n\nThe scanner only runs after explicit consent.\nPasswords, cookies, messages, photos and personal documents are not collected."),
            new Rectangle(24, 65, 710, 170),
            10.2F,
            TextSecondary));

        var privacy = new GuidedActionButton
        {
            Text = L("Política de Privacidade ↗", "Política de Privacidad ↗", "Privacy Policy ↗"),
            Bounds = new Rectangle(24, 252, 220, 44)
        };
        StyleGhostButton(privacy);
        privacy.Click += (_, _) => OpenUrl(PrivacyUrl);
        card.Controls.Add(privacy);

        var terms = new GuidedActionButton
        {
            Text = L("Rever termos no app", "Revisar términos", "Review terms"),
            Bounds = new Rectangle(260, 252, 190, 44)
        };
        StyleGhostButton(terms);
        terms.Click += (_, _) => ShowTermsGate();
        card.Controls.Add(terms);

        var language = new GuidedActionButton
        {
            Text = L("🌐  Alterar idioma", "🌐  Cambiar idioma", "🌐  Change language"),
            Bounds = new Rectangle(466, 252, 190, 44)
        };
        StyleGhostButton(language);
        language.Click += (_, _) => ShowLanguageGate();
        card.Controls.Add(language);

        var sound = new GuidedActionButton
        {
            Text = _soundEnabled
                ? L("🔊  Sons da interface: ligados", "🔊  Sonidos: activados", "🔊  Interface sounds: on")
                : L("🔇  Sons da interface: desligados", "🔇  Sonidos: desactivados", "🔇  Interface sounds: off"),
            Bounds = new Rectangle(24, 316, 260, 46)
        };
        StyleGhostButton(sound);
        sound.Click += (_, _) =>
        {
            _soundEnabled = !_soundEnabled;
            sound.Text = _soundEnabled
                ? L("🔊  Sons da interface: ligados", "🔊  Sonidos: activados", "🔊  Interface sounds: on")
                : L("🔇  Sons da interface: desligados", "🔇  Sonidos: desactivados", "🔇  Interface sounds: off");

            if (_soundEnabled)
                PlayUiClick();
        };
        card.Controls.Add(sound);

        card.Controls.Add(MakeLabel(
            L(
                "Os sons são discretos e podem ser desativados a qualquer momento.",
                "Los sonidos son discretos y pueden desactivarse en cualquier momento.",
                "Sounds are subtle and can be disabled at any time."),
            new Rectangle(302, 328, 430, 24),
            8F,
            TextDim));

        _surface.Controls.Add(card);
        SetHeaderState("READY", Accent);
    }

    private void FadeTimer_Tick(object? sender, EventArgs e)
    {
        Opacity = Math.Min(1d, Opacity + 0.08d);

        if (Opacity >= 1d)
        {
            Opacity = 1d;
            _fadeTimer.Stop();
        }
    }

    private void UpdateWindowRegion()
    {
        if (!IsHandleCreated)
            return;

        if (WindowState == FormWindowState.Maximized)
        {
            Region? previous = Region;
            Region = null;
            previous?.Dispose();
            return;
        }

        ApplyRoundedRegion(this, 18);
    }

    private static void AttachRoundedRegion(Control control, int radius)
    {
        void Apply(object? _, EventArgs __) =>
            ApplyRoundedRegion(control, radius);

        control.SizeChanged -= Apply;
        control.SizeChanged += Apply;
        ApplyRoundedRegion(control, radius);
    }

    private static void ApplyRoundedRegion(Control control, int radius)
    {
        if (control.Width <= 1 || control.Height <= 1)
            return;

        using GraphicsPath path =
            VorkenGeometry.CreateRoundedRectangle(
                new Rectangle(0, 0, control.Width, control.Height),
                radius);

        Region next = new(path);
        Region? previous = control.Region;
        control.Region = next;
        previous?.Dispose();
    }

    private void MotionTimer_Tick(object? sender, EventArgs e)
    {
        _motion += 0.055f;
        if (_motion > 10000f)
            _motion = 0f;

        _surface.Motion = _motion;
        _surface.Invalidate();
    }

    private VorkenCard MakeCard(Rectangle bounds)
    {
        return new VorkenCard
        {
            Bounds = bounds,
            BackColor = Color.FromArgb(16, 29, 49),
            BorderColor = Border
        };
    }

    private Label MakeBadge(string text)
    {
        var badge = new Label
        {
            Text = "●  " + text,
            AutoSize = true,
            Padding = new Padding(12, 6, 12, 6),
            BackColor = Color.FromArgb(20, 45, 81),
            ForeColor = Accent,
            Font = new Font("Consolas", 8.2F, FontStyle.Bold)
        };

        AttachRoundedRegion(badge, 7);
        return badge;
    }

    private Label MakeSectionTitle(string text, int x, int y)
    {
        return MakeLabel(
            text,
            new Rectangle(x, y, 350, 24),
            8.3F,
            Accent,
            FontStyle.Bold,
            "Consolas");
    }

    private static Label MakeLabel(
        string text,
        Rectangle bounds,
        float size,
        Color color,
        FontStyle style = FontStyle.Regular,
        string family = "Segoe UI")
    {
        return new Label
        {
            Text = text,
            Bounds = bounds,
            ForeColor = color,
            BackColor = Color.Transparent,
            Font = new Font(family, size, style),
            AutoEllipsis = true
        };
    }

    private LinkLabel MakeLink(string text, int x, int y, Action action)
    {
        var link = new LinkLabel
        {
            Text = text,
            AutoSize = true,
            Location = new Point(x, y),
            Font = new Font("Segoe UI", 7.8F),
            LinkColor = AccentSoft,
            ActiveLinkColor = Accent,
            VisitedLinkColor = AccentSoft,
            BackColor = Color.Transparent
        };
        link.LinkClicked += (_, _) => action();
        return link;
    }

    private void AddFeatureRow(
        Control parent,
        string icon,
        string title,
        string subtitle,
        int x,
        int y,
        int width)
    {
        parent.Controls.Add(MakeLabel(icon, new Rectangle(x, y + 4, 36, 28), 15F, Accent, FontStyle.Bold));
        parent.Controls.Add(MakeLabel(title, new Rectangle(x + 48, y, width - 54, 22), 9.3F, TextPrimary));
        parent.Controls.Add(MakeLabel(subtitle, new Rectangle(x + 48, y + 22, width - 54, 18), 7.7F, TextDim));

        if (y < 300)
        {
            parent.Controls.Add(new Panel
            {
                Bounds = new Rectangle(x + 48, y + 43, width - 60, 1),
                BackColor = Color.FromArgb(15, 51, 61)
            });
        }
    }

    private Label AddStageRow(
        Control parent,
        int index,
        string title,
        string subtitle,
        int x,
        int y)
    {
        parent.Controls.Add(MakeLabel(
            index switch
            {
                0 => "◆",
                1 => "⚙",
                2 => "▤",
                3 => "↕",
                4 => "⇩",
                5 => "◇",
                6 => "⌘",
                _ => "▤"
            },
            new Rectangle(x, y + 3, 30, 30),
            14F,
            index <= 2 ? Accent : TextDim,
            FontStyle.Bold));

        parent.Controls.Add(MakeLabel(title, new Rectangle(x + 40, y, 225, 20), 8.7F, TextPrimary));
        parent.Controls.Add(MakeLabel(subtitle, new Rectangle(x + 40, y + 20, 250, 18), 7F, TextDim));

        var state = MakeLabel(
            "○  PENDENTE",
            new Rectangle(288, y + 7, 95, 20),
            7.2F,
            TextDim,
            FontStyle.Bold,
            "Consolas");
        state.TextAlign = ContentAlignment.MiddleRight;
        parent.Controls.Add(state);
        return state;
    }

    private Panel MakeMiniStatus(
        string label,
        string value,
        string subtitle,
        int x,
        int y,
        int width)
    {
        var panel = new BorderedPanel
        {
            Bounds = new Rectangle(x, y, width, 92),
            BackColor = Color.FromArgb(16, 29, 49),
            BorderColor = Border
        };

        panel.Controls.Add(MakeLabel(
            label,
            new Rectangle(14, 12, width - 28, 18),
            7.1F,
            TextDim,
            FontStyle.Bold,
            "Consolas"));
        panel.Controls.Add(MakeLabel(
            value,
            new Rectangle(14, 38, width - 28, 22),
            9.1F,
            TextPrimary,
            FontStyle.Bold));
        panel.Controls.Add(MakeLabel(
            subtitle,
            new Rectangle(14, 64, width - 28, 16),
            6.6F,
            TextDim,
            FontStyle.Bold));
        return panel;
    }

    private Panel MakeStatBox(string icon, string title, Label valueLabel, int x, int y)
    {
        var panel = new BorderedPanel
        {
            Bounds = new Rectangle(x, y, 154, 62),
            BackColor = Color.FromArgb(16, 29, 49),
            BorderColor = Border
        };
        panel.Controls.Add(MakeLabel(icon, new Rectangle(12, 13, 25, 26), 13F, Accent, FontStyle.Bold));
        panel.Controls.Add(MakeLabel(title, new Rectangle(42, 8, 103, 18), 6.4F, TextDim, FontStyle.Bold));
        valueLabel.Bounds = new Rectangle(42, 28, 104, 24);
        valueLabel.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
        valueLabel.ForeColor = TextPrimary;
        valueLabel.BackColor = Color.Transparent;
        panel.Controls.Add(valueLabel);
        return panel;
    }

    private Panel MakeStaticStatBox(
        string icon,
        string title,
        string value,
        string subtitle,
        int x,
        int y)
    {
        var panel = new BorderedPanel
        {
            Bounds = new Rectangle(x, y, 154, 62),
            BackColor = Color.FromArgb(16, 29, 49),
            BorderColor = Border
        };
        panel.Controls.Add(MakeLabel(icon, new Rectangle(12, 13, 25, 26), 13F, Accent, FontStyle.Bold));
        panel.Controls.Add(MakeLabel(title, new Rectangle(42, 7, 105, 16), 6.4F, TextDim, FontStyle.Bold));
        panel.Controls.Add(MakeLabel(value, new Rectangle(42, 24, 105, 20), 8.8F, TextPrimary, FontStyle.Bold));
        panel.Controls.Add(MakeLabel(subtitle, new Rectangle(42, 43, 105, 15), 6.3F, TextDim, FontStyle.Bold));
        return panel;
    }

    private Panel MakeFooterItem(string icon, string title, string subtitle, int x)
    {
        var panel = new Panel
        {
            Bounds = new Rectangle(x, 4, 280, 32),
            BackColor = Color.Transparent
        };
        panel.Controls.Add(MakeLabel(icon, new Rectangle(0, 2, 30, 28), 15F, Accent, FontStyle.Bold));
        panel.Controls.Add(MakeLabel(title, new Rectangle(38, 0, 220, 17), 7.4F, Accent, FontStyle.Bold));
        panel.Controls.Add(MakeLabel(subtitle, new Rectangle(38, 16, 230, 16), 6.8F, TextDim));
        return panel;
    }

    private void SetHeaderState(string state, Color color)
    {
        _headerStatus.Text = "●  " + state;
        _headerStatus.ForeColor = color;
        _headerStatus.BackColor = Color.FromArgb(20, 40, 71);
    }

    private void StylePrimaryButton(Button button)
    {
        if (button is GuidedActionButton guided) guided.Primary = true;
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 1;
        button.FlatAppearance.BorderColor = Color.FromArgb(79, 143, 255);
        button.FlatAppearance.MouseDownBackColor = Color.FromArgb(29, 78, 216);
        button.BackColor = Accent;
        button.ForeColor = Color.FromArgb(255, 255, 255);
        button.Font = new Font("Segoe UI", 12F, FontStyle.Bold);
        button.Cursor = Cursors.Hand;
        button.TabStop = true;
        if (button is not GuidedActionButton) AttachRoundedRegion(button, 14);
        EnhanceButton(button);

        button.MouseEnter += (_, _) =>
        {
            if (button.Enabled)
                button.BackColor = Color.FromArgb(59, 130, 246);
        };

        button.MouseLeave += (_, _) =>
        {
            if (button.Enabled)
                button.BackColor = Accent;
        };
    }

    private void StyleGhostButton(Button button)
    {
        if (button is GuidedActionButton guided) guided.Primary = false;
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderColor = BorderBright;
        button.FlatAppearance.BorderSize = 1;
        button.BackColor = Color.FromArgb(16, 29, 49);
        button.ForeColor = TextPrimary;
        button.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
        button.Cursor = Cursors.Hand;
        button.FlatAppearance.MouseDownBackColor = Color.FromArgb(25, 55, 100);
        if (button is not GuidedActionButton) AttachRoundedRegion(button, 13);
        EnhanceButton(button);

        Color normalBack = button.BackColor;
        Color normalFore = button.ForeColor;

        button.MouseEnter += (_, _) =>
        {
            button.BackColor = Color.FromArgb(25, 49, 84);
            button.ForeColor = Accent;
            button.FlatAppearance.BorderColor = AccentSoft;
        };

        button.MouseLeave += (_, _) =>
        {
            button.BackColor = normalBack;
            button.ForeColor = normalFore;
            button.FlatAppearance.BorderColor = BorderBright;
        };
    }

    private void EnhanceButton(Button button)
    {
        if (!_enhancedButtons.Add(button))
            return;

        button.Cursor = Cursors.Hand;
        button.MouseEnter += (_, _) =>
        {
            if (button.Enabled)
                PlayUiHover();
        };
        button.Click += (_, _) => PlayUiClick();
        button.GotFocus += (_, _) =>
        {
            if (button.Enabled)
                button.FlatAppearance.BorderColor = Accent;
        };
        button.LostFocus += (_, _) =>
        {
            if (button.Enabled && button.BackColor != Accent)
                button.FlatAppearance.BorderColor = BorderBright;
        };
    }

    private void WireUiSounds(Control control)
    {
        if (control is Button button) EnhanceButton(button);
        control.ControlAdded -= OnSoundControlAdded;
        control.ControlAdded += OnSoundControlAdded;
        foreach (Control child in control.Controls) WireUiSounds(child);
    }

    private void OnSoundControlAdded(object? sender, ControlEventArgs e)
    {
        if (e.Control is not null) WireUiSounds(e.Control);
    }

    private void PlayUiHover() { if (_soundEnabled) _uiAudio.Hover(); }
    private void PlayUiClick() { if (_soundEnabled) _uiAudio.Click(); }

    private static string BuildFindingRowText(AgentFindingSnapshot finding)
    {
        string title = Ellipsize(finding.Title ?? "Evidência detectada", 38);
        string value = Ellipsize(finding.ArtifactValue ?? "—", 52);
        return title + Environment.NewLine + value + "   ›";
    }

    private static string SeverityLabel(string? severity)
    {
        return severity?.ToLowerInvariant() switch
        {
            "critical" => "CRÍTICO",
            "high" => "REVISAR",
            "medium" => "REVISAR",
            "low" => "BAIXO",
            _ => "INFO"
        };
    }

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalMinutes >= 1)
            return $"{(int)duration.TotalMinutes} min {duration.Seconds:00} s";
        return $"{Math.Max(0, duration.Seconds)} s";
    }

    private static string Ellipsize(string value, int max)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "—";

        string normalized = value.Replace("\r", " ").Replace("\n", " ").Trim();
        return normalized.Length <= max
            ? normalized
            : normalized[..Math.Max(1, max - 1)] + "…";
    }

    private static void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url)
            {
                UseShellExecute = true
            });
        }
        catch
        {
        }
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        _clientResultPollTimer.Stop();
        if (_remoteSupport is not null)
            _remoteSupport.StopAsync().GetAwaiter().GetResult();
        if (!_running)
            return;

        DialogResult answer = MessageBox.Show(
            this,
            "A análise ainda está em andamento. Fechar agora pode interromper o envio dos dados. Deseja fechar mesmo assim?",
            "Vorken AntiCheat",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);

        if (answer != DialogResult.Yes)
            e.Cancel = true;
    }

    private void Header_MouseDown(object? sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left || WindowState == FormWindowState.Maximized)
            return;

        ReleaseCapture();
        SendMessage(Handle, 0xA1, 0x2, 0);
    }

    private const int SbVert = 1;
    private const uint SifRange = 0x0001;
    private const uint SifPage = 0x0002;
    private const uint SifPos = 0x0004;

    [StructLayout(LayoutKind.Sequential)]
    private struct ScrollInfo
    {
        public uint cbSize;
        public uint fMask;
        public int nMin;
        public int nMax;
        public uint nPage;
        public int nPos;
        public int nTrackPos;
    }

    private static bool IsRichTextBoxScrolledToBottom(RichTextBox box)
    {
        if (!box.IsHandleCreated)
            return false;

        var info = new ScrollInfo
        {
            cbSize = (uint)Marshal.SizeOf<ScrollInfo>(),
            fMask = SifRange | SifPage | SifPos
        };

        if (!GetScrollInfo(box.Handle, SbVert, ref info))
            return false;

        int page = Math.Max(1, (int)info.nPage);
        int bottom = Math.Max(info.nMin, info.nMax - page + 1);

        // Small tolerance accounts for Win32 scrollbar rounding at high DPI.
        return info.nPos >= bottom - 1;
    }

    [DllImport("user32.dll")]
    private static extern bool GetScrollInfo(
        IntPtr hwnd,
        int nBar,
        ref ScrollInfo lpsi);

    [DllImport("user32.dll")]
    private static extern bool ReleaseCapture();

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, int wParam, int lParam);


}

internal sealed record ManualToolDefinition(
    string Name,
    string Description,
    string DownloadUrl);

internal enum AnimatedSurfaceMode
{
    Idle,
    Scanning,
    Complete,
    Error
}

internal static class VorkenGeometry
{
    internal static GraphicsPath CreateRoundedRectangle(
        Rectangle bounds,
        int radius)
    {
        var path = new GraphicsPath();

        int safeRadius = Math.Max(
            1,
            Math.Min(
                radius,
                Math.Min(bounds.Width, bounds.Height) / 2));

        int diameter = safeRadius * 2;
        Rectangle arc = new(bounds.X, bounds.Y, diameter, diameter);

        path.AddArc(arc, 180, 90);
        arc.X = bounds.Right - diameter - 1;
        path.AddArc(arc, 270, 90);
        arc.Y = bounds.Bottom - diameter - 1;
        path.AddArc(arc, 0, 90);
        arc.X = bounds.X;
        path.AddArc(arc, 90, 90);
        path.CloseFigure();

        return path;
    }
}

internal sealed class BorderFrame : Panel
{
    internal Color BorderColor { get; set; } = Color.FromArgb(55, 88, 135);
    internal int CornerRadius { get; set; } = 18;

    internal BorderFrame()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
        Padding = new Padding(3, 3, 3, 3);
    }

    protected override void OnResize(EventArgs eventargs)
    {
        base.OnResize(eventargs);
        UpdateRegion();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        if (Width <= 1 || Height <= 1)
            return;

        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;

        using GraphicsPath path =
            VorkenGeometry.CreateRoundedRectangle(
                new Rectangle(1, 1, Width - 3, Height - 3),
                CornerRadius);

        using var pen = new Pen(BorderColor, 1.5F);
        e.Graphics.DrawPath(pen, path);
    }

    private void UpdateRegion()
    {
        if (Width <= 1 || Height <= 1)
            return;

        using GraphicsPath path =
            VorkenGeometry.CreateRoundedRectangle(
                new Rectangle(0, 0, Width, Height),
                CornerRadius);

        Region? previous = Region;
        Region = new Region(path);
        previous?.Dispose();
    }
}

internal class BorderedPanel : Panel
{
    internal Color BorderColor { get; set; } = Color.FromArgb(35, 53, 78);
    internal int CornerRadius { get; set; } = 14;

    internal BorderedPanel()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
    }

    protected override void OnResize(EventArgs eventargs)
    {
        base.OnResize(eventargs);
        UpdateRegion();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        if (Width <= 1 || Height <= 1)
            return;

        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;

        using GraphicsPath path =
            VorkenGeometry.CreateRoundedRectangle(
                new Rectangle(0, 0, Width - 1, Height - 1),
                CornerRadius);

        using var pen = new Pen(BorderColor, 1);
        e.Graphics.DrawPath(pen, path);
    }

    private void UpdateRegion()
    {
        if (Width <= 1 || Height <= 1)
            return;

        using GraphicsPath path =
            VorkenGeometry.CreateRoundedRectangle(
                new Rectangle(0, 0, Width, Height),
                CornerRadius);

        Region? previous = Region;
        Region = new Region(path);
        previous?.Dispose();
    }
}

internal sealed class VorkenCard : BorderedPanel
{
    internal VorkenCard()
    {
        CornerRadius = 16;
        Cursor = Cursors.Default;
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        if (Width < 2 || Height < 2) return;
        using var background = new LinearGradientBrush(ClientRectangle, Color.FromArgb(13, 31, 49), Color.FromArgb(7, 19, 32), 24F);
        e.Graphics.FillRectangle(background, ClientRectangle);
    }

}

internal sealed class AnimatedSurface : Panel
{
    internal float Motion { get; set; }
    internal AnimatedSurfaceMode Mode { get; set; }

    internal AnimatedSurface()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
        BackColor = Color.FromArgb(11, 17, 27);
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        using (var background = new LinearGradientBrush(
            ClientRectangle,
            Color.FromArgb(11, 17, 27),
            Color.FromArgb(16, 28, 47),
            LinearGradientMode.Vertical))
        {
            g.FillRectangle(background, ClientRectangle);
        }


    }
}

internal sealed class ScannerPulseControl : Control
{
    private readonly System.Windows.Forms.Timer _timer = new();
    private float _phase;
    private const int CornerRadius = 12;

    internal bool Scanning { get; set; }
    internal string Caption { get; set; } = "READY TO SCAN";

    internal ScannerPulseControl()
    {
        DoubleBuffered = true;

        _timer.Interval = 40;
        _timer.Tick += (_, _) =>
        {
            _phase += 0.04f;
            Invalidate();
        };
        _timer.Start();
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);

        if (Width <= 1 || Height <= 1)
            return;

        using GraphicsPath path =
            VorkenGeometry.CreateRoundedRectangle(
                new Rectangle(0, 0, Width, Height),
                CornerRadius);

        Region? previous = Region;
        Region = new Region(path);
        previous?.Dispose();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);

        using var borderPen = new Pen(Color.FromArgb(70, 43, 239, 201), 1);
        using var gridPen = new Pen(Color.FromArgb(15, 43, 239, 201), 1);

        for (int x = 0; x < Width; x += 28)
            g.DrawLine(gridPen, x, 0, x, Height);

        for (int y = 0; y < Height; y += 28)
            g.DrawLine(gridPen, 0, y, Width, y);

        using (GraphicsPath borderPath =
            VorkenGeometry.CreateRoundedRectangle(
                new Rectangle(0, 0, Width - 1, Height - 1),
                CornerRadius))
        {
            g.DrawPath(borderPen, borderPath);
        }

        int cx = Width / 2;
        int cy = (Height - 34) / 2;
        int maxRadius = Math.Min(Width, Height - 34) / 2 - 18;

        using var ringPen = new Pen(Color.FromArgb(95, 43, 239, 201), 1);
        for (int i = 1; i <= 4; i++)
        {
            int r = maxRadius * i / 4;
            g.DrawEllipse(ringPen, cx - r, cy - r, r * 2, r * 2);
        }

        g.DrawLine(ringPen, cx - maxRadius, cy, cx + maxRadius, cy);
        g.DrawLine(ringPen, cx, cy - maxRadius, cx, cy + maxRadius);

        float angle = Scanning ? _phase * 1.7f : -0.8f;
        PointF center = new(cx, cy);
        PointF edgeA = new(
            cx + (float)Math.Cos(angle - 0.24f) * maxRadius,
            cy + (float)Math.Sin(angle - 0.24f) * maxRadius);
        PointF edgeB = new(
            cx + (float)Math.Cos(angle + 0.24f) * maxRadius,
            cy + (float)Math.Sin(angle + 0.24f) * maxRadius);

        using var wedge = new SolidBrush(Color.FromArgb(55, 43, 239, 201));
        g.FillPolygon(wedge, new[] { center, edgeA, edgeB });

        using var sweepPen = new Pen(Color.FromArgb(210, 43, 239, 201), 2);
        PointF sweep = new(
            cx + (float)Math.Cos(angle) * maxRadius,
            cy + (float)Math.Sin(angle) * maxRadius);
        g.DrawLine(sweepPen, center, sweep);

        using var centerBrush = new SolidBrush(Color.FromArgb(230, 43, 239, 201));
        g.FillEllipse(centerBrush, cx - 6, cy - 6, 12, 12);

        int[] dotAngles = { 38, 122, 208, 308 };
        foreach (int degree in dotAngles)
        {
            double rad = (degree * Math.PI / 180d) + (Scanning ? _phase * 0.07d : 0d);
            int r = (int)(maxRadius * 0.65);
            int dx = cx + (int)(Math.Cos(rad) * r);
            int dy = cy + (int)(Math.Sin(rad) * r);
            g.FillEllipse(centerBrush, dx - 3, dy - 3, 6, 6);
        }

        using var textBrush = new SolidBrush(Color.FromArgb(37, 99, 235));
        using var font = new Font("Consolas", 7.4F, FontStyle.Bold);
        g.DrawString(Caption, font, textBrush, 8, Height - 25);

        for (int i = 0; i < 6; i++)
        {
            using var block = new SolidBrush(
                i < (Scanning ? 4 : 2)
                    ? Color.FromArgb(220, 43, 239, 201)
                    : Color.FromArgb(35, 43, 239, 201));
            g.FillRectangle(block, Width - 66 + (i * 9), Height - 21, 6, 6);
        }
    }
}
