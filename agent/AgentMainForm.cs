using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows.Forms;

namespace Vorken.Agent;

internal sealed class AgentMainForm : Form
{
    private const string PrivacyUrl = "https://vorkenac.guerrafriarust.com.br/privacy";
    private const string TermsUrl = "https://vorkenac.guerrafriarust.com.br/terms";

    private readonly string[] _args;
    private readonly AnimatedSurface _surface = new();
    private readonly Panel _header = new();
    private readonly Panel _nav = new();
    private readonly Label _headerStatus = new();
    private readonly TextBox _activityBox = new();
    private readonly Panel _progressTrack = new();
    private readonly Panel _progressFill = new();
    private readonly Label _progressPercentLabel = new();
    private readonly Label _progressEtaLabel = new();
    private readonly Label _elapsedLabel = new();
    private readonly Label _artifactCountLabel = new();
    private readonly Label _deviceCountLabel = new();
    private readonly CheckBox _consentCheck = new();
    private readonly Button _startButton = new();
    private readonly Button _closeButton = new();
    private readonly System.Windows.Forms.Timer _motionTimer = new();
    private readonly System.Windows.Forms.Timer _scanTimer = new();

    private readonly List<Label> _stepStateLabels = new();
    private readonly List<string> _activityLines = new();
    private readonly List<AgentFindingSnapshot> _visibleFindings = new();

    private Panel? _evidenceDetailPanel;
    private DateTime _scanStartedAt;
    private AgentRunResult? _lastRun;
    private bool _running;
    private bool _finished;
    private float _motion;
    private int _progressPercent;
    private int _artifactCount;
    private int _devicesSeen;

    private static readonly Color Background = Color.FromArgb(4, 10, 15);
    private static readonly Color Header = Color.FromArgb(5, 15, 22);
    private static readonly Color Surface = Color.FromArgb(6, 18, 25);
    private static readonly Color SurfaceAlt = Color.FromArgb(8, 26, 34);
    private static readonly Color Border = Color.FromArgb(21, 61, 76);
    private static readonly Color BorderBright = Color.FromArgb(24, 117, 141);
    private static readonly Color Accent = Color.FromArgb(43, 239, 201);
    private static readonly Color AccentSoft = Color.FromArgb(20, 181, 157);
    private static readonly Color Blue = Color.FromArgb(55, 166, 255);
    private static readonly Color TextPrimary = Color.FromArgb(244, 249, 249);
    private static readonly Color TextSecondary = Color.FromArgb(178, 194, 202);
    private static readonly Color TextDim = Color.FromArgb(105, 129, 140);
    private static readonly Color Warning = Color.FromArgb(255, 190, 55);
    private static readonly Color Danger = Color.FromArgb(255, 72, 88);
    private static readonly Color Success = Color.FromArgb(43, 239, 201);

    internal AgentMainForm(string[] args)
    {
        _args = args;

        Text = "Vorken Anti Cheat";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1280, 900);
        MinimumSize = new Size(1160, 820);
        BackColor = Background;
        ForeColor = TextPrimary;
        Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point);
        FormBorderStyle = FormBorderStyle.None;
        DoubleBuffered = true;

        BuildShell();
        ShowConsentView();

        _motionTimer.Interval = 36;
        _motionTimer.Tick += MotionTimer_Tick;
        _motionTimer.Start();

        _scanTimer.Interval = 1000;
        _scanTimer.Tick += ScanTimer_Tick;

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
        _header.BackColor = Header;
        _header.MouseDown += Header_MouseDown;

        var brandMark = new Label
        {
            Text = "V",
            AutoSize = false,
            Size = new Size(52, 52),
            Location = new Point(40, 18),
            TextAlign = ContentAlignment.MiddleCenter,
            BackColor = Accent,
            ForeColor = Color.FromArgb(2, 23, 25),
            Font = new Font("Segoe UI", 22F, FontStyle.Bold)
        };

        var brandName = new Label
        {
            Text = "VORKEN",
            AutoSize = true,
            Location = new Point(110, 17),
            Font = new Font("Segoe UI", 17F, FontStyle.Bold),
            ForeColor = TextPrimary,
            BackColor = Color.Transparent
        };

        var brandCaption = new Label
        {
            Text = "ANTI CHEAT · SECURE SCAN SESSION",
            AutoSize = true,
            Location = new Point(112, 50),
            Font = new Font("Consolas", 8.5F, FontStyle.Bold),
            ForeColor = Accent,
            BackColor = Color.Transparent
        };

        _nav.Location = new Point(430, 20);
        _nav.Size = new Size(565, 58);
        _nav.BackColor = Color.Transparent;
        _nav.Visible = false;

        AddNavButton("⌂", "Início", 0, () => ShowCompletionHome());
        AddNavButton("⚙", "Análise", 1, ShowAnalysisSummaryView);
        AddNavButton("≡", "Resultados", 2, () =>
        {
            if (_lastRun is not null)
                ShowResultsView(_lastRun);
        });
        AddNavButton("◷", "Histórico", 3, ShowHistoryView);
        AddNavButton("⚙", "Configurações", 4, ShowSettingsView);

        _headerStatus.Text = "●  READY";
        _headerStatus.AutoSize = false;
        _headerStatus.Size = new Size(140, 36);
        _headerStatus.Location = new Point(1020, 35);
        _headerStatus.TextAlign = ContentAlignment.MiddleCenter;
        _headerStatus.Font = new Font("Consolas", 8.5F, FontStyle.Bold);
        _headerStatus.ForeColor = Accent;
        _headerStatus.BackColor = Color.FromArgb(6, 31, 36);

        var minButton = MakeWindowButton("—", 1162);
        minButton.Click += (_, _) => WindowState = FormWindowState.Minimized;

        var maxButton = MakeWindowButton("□", 1200);
        maxButton.Click += (_, _) =>
            WindowState = WindowState == FormWindowState.Maximized
                ? FormWindowState.Normal
                : FormWindowState.Maximized;

        var exitButton = MakeWindowButton("×", 1238);
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

        outer.Controls.Add(_surface);
        outer.Controls.Add(_header);
        Controls.Add(outer);

        Resize += (_, _) =>
        {
            _headerStatus.Left = Math.Max(860, ClientSize.Width - 260);
            minButton.Left = ClientSize.Width - 118;
            maxButton.Left = ClientSize.Width - 80;
            exitButton.Left = ClientSize.Width - 42;
        };
    }

    private Button MakeWindowButton(string text, int x)
    {
        var button = new Button
        {
            Text = text,
            Location = new Point(x, 2),
            Size = new Size(38, 30),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.Transparent,
            ForeColor = TextPrimary,
            Font = new Font("Segoe UI", 11F),
            TabStop = false
        };
        button.FlatAppearance.BorderSize = 0;
        button.FlatAppearance.MouseOverBackColor = Color.FromArgb(20, 45, 55);
        return button;
    }

    private void AddNavButton(string icon, string text, int index, Action action)
    {
        var button = new Button
        {
            Text = icon + Environment.NewLine + text,
            Tag = index,
            Location = new Point(index * 108, 0),
            Size = new Size(104, 58),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.Transparent,
            ForeColor = TextSecondary,
            Font = new Font("Segoe UI", 8.6F),
            Cursor = Cursors.Hand
        };
        button.FlatAppearance.BorderSize = 0;
        button.FlatAppearance.MouseOverBackColor = Color.FromArgb(8, 35, 42);
        button.Click += (_, _) =>
        {
            SetActiveNav(index);
            action();
        };
        _nav.Controls.Add(button);
    }

    private void SetActiveNav(int index)
    {
        foreach (Control control in _nav.Controls)
        {
            if (control is not Button button)
                continue;

            bool active = Convert.ToInt32(button.Tag) == index;
            button.ForeColor = active ? Accent : TextSecondary;
            button.BackColor = active ? Color.FromArgb(7, 44, 49) : Color.Transparent;
            button.FlatAppearance.BorderSize = active ? 1 : 0;
            button.FlatAppearance.BorderColor = active ? AccentSoft : Color.Transparent;
        }
    }

    private void ShowConsentView()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Idle;
        _nav.Visible = false;
        _finished = false;

        var badge = MakeBadge("PLAYER INTEGRITY   ·   EVIDENCE FIRST");
        badge.Location = new Point(46, 32);

        var title = MakeLabel(
            "Análise técnica\ncom evidência real.",
            new Rectangle(46, 78, 700, 120),
            35F,
            TextPrimary,
            FontStyle.Bold);
        title.Paint += (_, e) => { };

        var accentTitle = new Label
        {
            Text = "com evidência real.",
            AutoSize = true,
            Location = new Point(46, 133),
            Font = new Font("Segoe UI", 35F, FontStyle.Bold),
            ForeColor = Accent,
            BackColor = Color.Transparent
        };

        title.Text = "Análise técnica";

        var description = MakeLabel(
            "O Vorken realiza uma análise técnica e forense para revisar\n" +
            "indícios de trapaça em seu ambiente de forma segura e objetiva.\n" +
            "Menos ruído. Mais evidência real.",
            new Rectangle(48, 196, 700, 88),
            11.4F,
            TextSecondary);

        var analysisCard = MakeCard(new Rectangle(44, 286, 710, 365));
        analysisCard.Controls.Add(MakeSectionTitle("☷   O QUE SERÁ ANALISADO", 20, 18));

        string[] items =
        {
            "USB, dispositivos seriais e hardware relacionado|Histórico de conexão, dispositivos e drivers.",
            "Prefetch, BAM e cache do sistema|Execução de arquivos, atividade recente e rastros no sistema.",
            "Downloads e origem de arquivos|Arquivos obtidos, assinaturas digitais e integridade.",
            "Processos, serviços e módulos|Processos em execução, módulos carregados e injeções.",
            "Execução correlacionada|Linha do tempo e correlação de eventos relevantes.",
            "Integridade do ambiente|Verificação de modificações, hooks e ambiente de execução."
        };

        string[] icons = { "↕", "▤", "⇩", "⚙", "⌘", "◆" };
        for (int i = 0; i < items.Length; i++)
        {
            string[] parts = items[i].Split('|');
            AddFeatureRow(analysisCard, icons[i], parts[0], parts[1], 20, 54 + (i * 49), 660);
        }

        var privacy = new BorderedPanel
        {
            Bounds = new Rectangle(44, 664, 710, 80),
            BackColor = Color.FromArgb(25, 23, 10),
            BorderColor = Color.FromArgb(118, 86, 23)
        };
        privacy.Controls.Add(new Label
        {
            Text = "▣",
            Location = new Point(18, 22),
            Size = new Size(28, 28),
            Font = new Font("Segoe UI Symbol", 15F, FontStyle.Bold),
            ForeColor = Warning,
            BackColor = Color.Transparent
        });
        privacy.Controls.Add(MakeLabel(
            "PRIVACIDADE E SEUS DADOS",
            new Rectangle(55, 12, 300, 20),
            8.3F,
            Warning,
            FontStyle.Bold));
        privacy.Controls.Add(MakeLabel(
            "Não coletamos senhas, cookies, mensagens, fotos ou documentos pessoais.\n" +
            "A análise é focada exclusivamente em evidências técnicas relacionadas à trapaça.",
            new Rectangle(55, 34, 620, 40),
            8.8F,
            TextSecondary));

        var consentPanel = new Panel
        {
            Bounds = new Rectangle(44, 754, 710, 54),
            BackColor = Color.Transparent
        };

        _consentCheck.Text = "Li e concordo com a análise técnica descrita acima.";
        _consentCheck.AutoSize = true;
        _consentCheck.Location = new Point(0, 3);
        _consentCheck.ForeColor = TextPrimary;
        _consentCheck.BackColor = Color.Transparent;
        _consentCheck.Font = new Font("Segoe UI", 9.4F);
        _consentCheck.Checked = false;
        _consentCheck.CheckedChanged -= ConsentCheck_Changed;
        _consentCheck.CheckedChanged += ConsentCheck_Changed;

        consentPanel.Controls.Add(_consentCheck);
        consentPanel.Controls.Add(MakeLabel(
            "Entendo que o Vorken irá analisar apenas os dados listados, de forma segura e sob demanda.",
            new Rectangle(28, 29, 500, 18),
            7.3F,
            TextDim));

        var privacyLink = MakeLink("Política de Privacidade ↗", 530, 0, () => OpenUrl(PrivacyUrl));
        var termsLink = MakeLink("Termos de Uso ↗", 530, 26, () => OpenUrl(TermsUrl));
        consentPanel.Controls.Add(privacyLink);
        consentPanel.Controls.Add(termsLink);

        var scannerCard = MakeCard(new Rectangle(786, 34, 440, 710));
        scannerCard.Controls.Add(MakeLabel(
            "SECURE SESSION",
            new Rectangle(26, 28, 190, 22),
            8.5F,
            Accent,
            FontStyle.Bold,
            "Consolas"));
        scannerCard.Controls.Add(MakeLabel(
            "VORKEN SCANNER",
            new Rectangle(26, 60, 300, 38),
            18F,
            TextPrimary,
            FontStyle.Bold));
        scannerCard.Controls.Add(MakeLabel(
            "Scanner sob demanda.",
            new Rectangle(26, 96, 330, 24),
            11F,
            TextPrimary));
        scannerCard.Controls.Add(MakeLabel(
            "Coleta e análise de evidências técnicas\npara uma revisão baseada em evidências.",
            new Rectangle(26, 132, 360, 56),
            10.2F,
            TextSecondary));

        var radar = new ScannerPulseControl
        {
            Location = new Point(26, 195),
            Size = new Size(388, 270),
            BackColor = Color.FromArgb(4, 17, 23),
            Scanning = false,
            Caption = "READY TO SCAN"
        };
        scannerCard.Controls.Add(radar);

        scannerCard.Controls.Add(MakeMiniStatus("MODE", "◈   ON DEMAND", "ANÁLISE SOB DEMANDA", 26, 480, 188));
        scannerCard.Controls.Add(MakeMiniStatus("EXECUTION", "▣   USER MODE", "AMBIENTE ATUAL", 226, 480, 188));

        _startButton.Text = "▶  Iniciar análise   →";
        _startButton.Bounds = new Rectangle(26, 590, 388, 64);
        StylePrimaryButton(_startButton);
        _startButton.Enabled = false;
        _startButton.Click -= AcceptButton_Click;
        _startButton.Click += AcceptButton_Click;
        scannerCard.Controls.Add(_startButton);

        scannerCard.Controls.Add(MakeLabel(
            "SCANNER SEGURO   ·   RÁPIDO   ·   SEM RUÍDO",
            new Rectangle(68, 668, 310, 20),
            7.4F,
            TextDim,
            FontStyle.Bold,
            "Consolas"));

        _surface.Controls.Add(badge);
        _surface.Controls.Add(title);
        _surface.Controls.Add(accentTitle);
        _surface.Controls.Add(description);
        _surface.Controls.Add(analysisCard);
        _surface.Controls.Add(privacy);
        _surface.Controls.Add(consentPanel);
        _surface.Controls.Add(scannerCard);

        SetHeaderState("READY", Accent);
    }

    private void ConsentCheck_Changed(object? sender, EventArgs e)
    {
        _startButton.Enabled = _consentCheck.Checked;
        _startButton.BackColor = _consentCheck.Checked
            ? Accent
            : Color.FromArgb(33, 78, 75);
    }

    private async void AcceptButton_Click(object? sender, EventArgs e)
    {
        if (_running || !_consentCheck.Checked)
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

    private void ShowProgressView()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Scanning;
        _nav.Visible = false;
        _stepStateLabels.Clear();

        var badge = MakeBadge("SCAN EM ANDAMENTO   ·   EVIDÊNCIAS EM TEMPO REAL");
        badge.Location = new Point(48, 30);

        _surface.Controls.Add(badge);
        _surface.Controls.Add(MakeLabel(
            "Coleta técnica",
            new Rectangle(48, 75, 680, 58),
            35F,
            TextPrimary,
            FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            "em andamento.",
            new Rectangle(48, 126, 680, 58),
            35F,
            Accent,
            FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            "O Vorken está coletando e correlacionando evidências técnicas\n" +
            "do seu sistema. Mantenha esta janela aberta até a conclusão.",
            new Rectangle(50, 189, 760, 58),
            11.4F,
            TextSecondary));

        var progressCard = MakeCard(new Rectangle(44, 262, 790, 104));
        progressCard.Controls.Add(MakeSectionTitle("PROGRESSO DA ANÁLISE", 20, 14));

        _progressTrack.Bounds = new Rectangle(20, 48, 655, 18);
        _progressTrack.BackColor = Color.FromArgb(9, 41, 48);
        _progressTrack.Controls.Clear();

        _progressFill.Bounds = new Rectangle(0, 0, 20, 18);
        _progressFill.BackColor = Accent;
        _progressTrack.Controls.Add(_progressFill);

        _progressPercentLabel.Text = "3%";
        _progressPercentLabel.Bounds = new Rectangle(690, 37, 78, 38);
        _progressPercentLabel.Font = new Font("Segoe UI", 18F, FontStyle.Bold);
        _progressPercentLabel.ForeColor = Accent;
        _progressPercentLabel.TextAlign = ContentAlignment.MiddleRight;
        _progressPercentLabel.BackColor = Color.Transparent;

        _progressEtaLabel.Text = "Correlacionando evidências do sistema...";
        _progressEtaLabel.Bounds = new Rectangle(20, 72, 700, 22);
        _progressEtaLabel.Font = new Font("Segoe UI", 8.5F);
        _progressEtaLabel.ForeColor = TextSecondary;
        _progressEtaLabel.BackColor = Color.Transparent;

        progressCard.Controls.Add(_progressTrack);
        progressCard.Controls.Add(_progressPercentLabel);
        progressCard.Controls.Add(_progressEtaLabel);
        _surface.Controls.Add(progressCard);

        var stagesCard = MakeCard(new Rectangle(44, 380, 400, 390));
        stagesCard.Controls.Add(MakeSectionTitle("☷   ETAPAS DA ANÁLISE", 18, 15));

        string[] stages =
        {
            "Sessão validada|Verificação de integridade da sessão e ambiente.",
            "Integridade do ambiente|Análise de processos, drivers e hooks.",
            "Histórico de execução|Prefetch, BAM, eventos e registros.",
            "Dispositivos USB|Dispositivos seriais e histórico de conexão.",
            "Downloads e origem|Arquivos obtidos, cache e navegador.",
            "Processos e módulos|Processos em execução, módulos carregados.",
            "Correlação de evidências|Cruzamento de dados e detecção de padrões.",
            "Preparando relatório|Geração do relatório técnico."
        };

        for (int i = 0; i < stages.Length; i++)
        {
            string[] parts = stages[i].Split('|');
            var state = AddStageRow(stagesCard, i, parts[0], parts[1], 18, 52 + (i * 41));
            _stepStateLabels.Add(state);
        }

        var streamCard = MakeCard(new Rectangle(456, 380, 378, 390));
        streamCard.Controls.Add(MakeSectionTitle("▤   FLUXO DE EVIDÊNCIAS (TEMPO REAL)", 16, 15));
        streamCard.Controls.Add(new Label
        {
            Text = "● AO VIVO",
            Bounds = new Rectangle(286, 12, 76, 24),
            TextAlign = ContentAlignment.MiddleCenter,
            BackColor = Color.FromArgb(4, 45, 48),
            ForeColor = Accent,
            Font = new Font("Consolas", 7.3F, FontStyle.Bold)
        });

        _activityBox.Bounds = new Rectangle(14, 48, 350, 326);
        _activityBox.Multiline = true;
        _activityBox.ReadOnly = true;
        _activityBox.ScrollBars = ScrollBars.Vertical;
        _activityBox.BackColor = Color.FromArgb(3, 12, 18);
        _activityBox.ForeColor = Color.FromArgb(159, 183, 189);
        _activityBox.BorderStyle = BorderStyle.None;
        _activityBox.Font = new Font("Consolas", 8.1F);
        _activityBox.Clear();
        streamCard.Controls.Add(_activityBox);

        _surface.Controls.Add(stagesCard);
        _surface.Controls.Add(streamCard);

        var scannerCard = MakeCard(new Rectangle(858, 32, 366, 738));
        scannerCard.Controls.Add(MakeLabel(
            "SESSÃO SEGURA",
            new Rectangle(22, 26, 180, 20),
            8.3F,
            Accent,
            FontStyle.Bold,
            "Consolas"));
        scannerCard.Controls.Add(MakeLabel(
            "Vorken Scanner",
            new Rectangle(22, 58, 290, 38),
            18F,
            TextPrimary,
            FontStyle.Bold));
        scannerCard.Controls.Add(MakeLabel(
            "Análise técnica em andamento.",
            new Rectangle(22, 95, 300, 24),
            10.8F,
            TextPrimary));
        scannerCard.Controls.Add(MakeLabel(
            "Coletando, analisando e correlacionando\nevidências para gerar um relatório seguro\ne confiável.",
            new Rectangle(22, 130, 310, 64),
            9.4F,
            TextSecondary));

        var radar = new ScannerPulseControl
        {
            Location = new Point(22, 208),
            Size = new Size(322, 250),
            BackColor = Color.FromArgb(4, 17, 23),
            Scanning = true,
            Caption = "ESCANEANDO SISTEMA"
        };
        scannerCard.Controls.Add(radar);

        _elapsedLabel.Text = "00 min 00 s";
        _artifactCountLabel.Text = "0 itens";
        _deviceCountLabel.Text = "0 dispositivos";

        scannerCard.Controls.Add(MakeStatBox("◷", "TEMPO DECORRIDO", _elapsedLabel, 22, 474));
        scannerCard.Controls.Add(MakeStatBox("▤", "ARQUIVOS ANALISADOS", _artifactCountLabel, 188, 474));
        scannerCard.Controls.Add(MakeStatBox("↕", "DISPOSITIVOS REVISADOS", _deviceCountLabel, 22, 548));
        scannerCard.Controls.Add(MakeStaticStatBox("◈", "MODO DE ANÁLISE", "ON DEMAND", "SOB DEMANDA", 188, 548));

        var keepOpen = new BorderedPanel
        {
            Bounds = new Rectangle(22, 628, 322, 82),
            BackColor = Color.FromArgb(30, 25, 8),
            BorderColor = Color.FromArgb(129, 94, 23)
        };
        keepOpen.Controls.Add(MakeLabel("●", new Rectangle(15, 16, 22, 22), 12F, Warning, FontStyle.Bold));
        keepOpen.Controls.Add(MakeLabel(
            "Mantenha esta janela aberta",
            new Rectangle(44, 10, 250, 23),
            8.7F,
            Warning,
            FontStyle.Bold));
        keepOpen.Controls.Add(MakeLabel(
            "A análise continuará em segundo plano e o\nrelatório será preparado automaticamente.",
            new Rectangle(44, 34, 258, 42),
            8.1F,
            TextSecondary));
        scannerCard.Controls.Add(keepOpen);

        _surface.Controls.Add(scannerCard);

        var footer = new Panel
        {
            Bounds = new Rectangle(44, 783, 1180, 40),
            BackColor = Color.FromArgb(5, 18, 24)
        };
        footer.Controls.Add(MakeFooterItem("◆", "SCANNER ATIVO", "Coleta e análise de evidências em tempo real.", 12));
        footer.Controls.Add(MakeFooterItem("▣", "SESSÃO SEGURA", "Dados protegidos", 415));
        footer.Controls.Add(MakeFooterItem("▣", "SEM IMPACTO", "Uso otimizado de recursos", 705));

        var cancel = new Button
        {
            Text = "■  Cancelar análise",
            Bounds = new Rectangle(1000, 6, 166, 28)
        };
        StyleGhostButton(cancel);
        cancel.Click += (_, _) =>
        {
            MessageBox.Show(
                this,
                "Para preservar a integridade da coleta, feche a janela e confirme a interrupção caso realmente deseje cancelar.",
                "Vorken",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        };
        footer.Controls.Add(cancel);
        _surface.Controls.Add(footer);

        SetHeaderState("ANALISANDO", Accent);
        UpdateStageStates(0);
        UpdateProgressUi();
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
            _activityBox.AppendText(line + Environment.NewLine);
            _activityBox.SelectionStart = _activityBox.TextLength;
            _activityBox.ScrollToCaret();
        }

        ParseArtifactCount(clean);
        AdvanceScanForMessage(clean);
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

        if (lower.Contains("correl") || lower.Contains("filtro") || lower.Contains("gemini") ||
            lower.Contains("processando"))
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

    private void ShowResultsView(AgentRunResult result)
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

        _visibleFindings.Clear();
        if (snapshot?.Findings is not null)
            _visibleFindings.AddRange(snapshot.Findings);

        var badge = MakeBadge("RESULTADOS   ·   RELATÓRIO DE ANÁLISE");
        badge.Location = new Point(44, 24);
        _surface.Controls.Add(badge);

        _surface.Controls.Add(MakeLabel(
            success ? "Relatório priorizado." : "Análise interrompida.",
            new Rectangle(44, 70, 650, 58),
            33F,
            TextPrimary,
            FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            success ? "Análise concluída." : "Não foi possível concluir.",
            new Rectangle(44, 119, 650, 56),
            33F,
            success ? Accent : Danger,
            FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            success
                ? "O Vorken analisou os dados do sistema e classificou os achados\npor nível de severidade. A decisão final é feita por revisão humana."
                : "A coleta foi interrompida antes da conclusão. Consulte os detalhes técnicos abaixo.",
            new Rectangle(46, 180, 610, 58),
            10.4F,
            TextSecondary));

        var statusCard = MakeCard(new Rectangle(674, 38, 552, 182));
        statusCard.Controls.Add(MakeLabel(
            "STATUS DA ANÁLISE",
            new Rectangle(22, 18, 210, 22),
            8.4F,
            Accent,
            FontStyle.Bold,
            "Consolas"));
        statusCard.Controls.Add(MakeLabel(
            success ? "✓" : "!",
            new Rectangle(26, 55, 58, 58),
            30F,
            success ? Accent : Danger,
            FontStyle.Bold));
        statusCard.Controls.Add(MakeLabel(
            success ? "CONCLUÍDO" : "ERRO",
            new Rectangle(96, 61, 190, 36),
            16F,
            success ? Accent : Danger,
            FontStyle.Bold));
        statusCard.Controls.Add(MakeLabel(
            $"Duração da análise: {FormatDuration(DateTime.Now - _scanStartedAt)}\n" +
            $"Concluído em: {DateTime.Now:dd/MM/yyyy HH:mm}",
            new Rectangle(96, 108, 240, 52),
            8.8F,
            TextSecondary));

        var decision = new BorderedPanel
        {
            Bounds = new Rectangle(333, 18, 197, 140),
            BackColor = Color.FromArgb(24, 18, 8),
            BorderColor = success && (criticalCount > 0 || reviewCount > 0)
                ? Color.FromArgb(150, 96, 20)
                : Border
        };
        decision.Controls.Add(MakeLabel(
            success && (criticalCount > 0 || reviewCount > 0)
                ? "DECISÃO:\nREVISÃO MANUAL\nNECESSÁRIA"
                : success
                    ? "DECISÃO:\nRELATÓRIO PRONTO"
                    : "DECISÃO:\nREPETIR ANÁLISE",
            new Rectangle(18, 18, 165, 66),
            10.1F,
            success && (criticalCount > 0 || reviewCount > 0) ? Warning : TextPrimary,
            FontStyle.Bold));
        decision.Controls.Add(MakeLabel(
            success
                ? "Os achados foram enviados\npara revisão da equipe."
                : "O envio não foi concluído.",
            new Rectangle(18, 96, 165, 38),
            8.3F,
            TextSecondary));
        statusCard.Controls.Add(decision);
        _surface.Controls.Add(statusCard);

        var criticalCard = MakeFindingColumn(
            "⚠", "CRÍTICO", criticalCount, "Achados de alta severidade",
            Danger, new Rectangle(28, 258, 380, 292),
            _visibleFindings.Where(x => x.Severity is "critical" or "high").Take(4).ToList());

        var reviewCard = MakeFindingColumn(
            "!", "REVISAR", reviewCount, "Achados de média severidade",
            Warning, new Rectangle(420, 258, 380, 292),
            _visibleFindings.Where(x => x.Severity == "medium").Take(4).ToList());

        var inventoryCard = MakeInventoryColumn(
            inventoryCount,
            new Rectangle(812, 258, 414, 292));

        _surface.Controls.Add(criticalCard);
        _surface.Controls.Add(reviewCard);
        _surface.Controls.Add(inventoryCard);

        var summaryCard = MakeCard(new Rectangle(28, 565, 590, 230));
        summaryCard.Controls.Add(MakeSectionTitle("●   RESUMO DA ANÁLISE", 18, 16));
        summaryCard.Controls.Add(MakeSummaryMetric("⚠", criticalCount.ToString(), "Itens críticos", "Alta severidade", Danger, 18));
        summaryCard.Controls.Add(MakeSummaryMetric("!", reviewCount.ToString(), "Itens para revisão", "Média severidade", Warning, 196));
        summaryCard.Controls.Add(MakeSummaryMetric("▤", inventoryCount.ToString(), "Artefatos catalogados", "Baixo risco / inventário", Blue, 388));

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
        _evidenceDetailPanel.Controls.Add(MakeSectionTitle("DETALHES DA EVIDÊNCIA", 18, 15));
        _surface.Controls.Add(_evidenceDetailPanel);

        AgentFindingSnapshot? selected =
            _visibleFindings.FirstOrDefault(x => x.Severity is "critical" or "high")
            ?? _visibleFindings.FirstOrDefault();

        ShowEvidenceDetail(selected);

        SetHeaderState(success ? "CONCLUÍDO" : "ERRO", success ? Accent : Danger);
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

        card.Controls.Add(MakeLabel(icon, new Rectangle(18, 18, 42, 42), 21F, color, FontStyle.Bold));
        card.Controls.Add(MakeLabel(title, new Rectangle(67, 17, 160, 26), 13.5F, color, FontStyle.Bold));
        card.Controls.Add(new Label
        {
            Text = count.ToString(),
            Bounds = new Rectangle(230, 17, 36, 24),
            BackColor = Color.FromArgb(45, color),
            ForeColor = color,
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleCenter
        });
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
                Font = new Font("Segoe UI", 8.6F),
                Cursor = Cursors.Hand
            };
            row.FlatAppearance.BorderColor = Color.FromArgb(60, color);
            row.FlatAppearance.BorderSize = 1;
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
        card.Controls.Add(new Label
        {
            Text = count.ToString(),
            Bounds = new Rectangle(246, 17, 42, 24),
            BackColor = Color.FromArgb(25, 55, 100),
            ForeColor = Blue,
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleCenter
        });
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

        Color color = finding.Severity is "critical" or "high" ? Danger : Warning;

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
        if (_lastRun is null)
        {
            ShowConsentView();
            return;
        }

        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Complete;
        _nav.Visible = true;
        SetActiveNav(1);

        var badge = MakeBadge("ANÁLISE   ·   ATIVIDADE TÉCNICA");
        badge.Location = new Point(44, 34);
        _surface.Controls.Add(badge);
        _surface.Controls.Add(MakeLabel(
            "Atividade da coleta",
            new Rectangle(44, 78, 800, 56),
            31F,
            TextPrimary,
            FontStyle.Bold));
        _surface.Controls.Add(MakeLabel(
            "Registro técnico da sessão concluída.",
            new Rectangle(47, 135, 600, 28),
            10.5F,
            TextSecondary));

        var logCard = MakeCard(new Rectangle(44, 190, 1180, 570));
        logCard.Controls.Add(MakeSectionTitle("FLUXO DE EVIDÊNCIAS", 20, 18));

        var box = new TextBox
        {
            Bounds = new Rectangle(20, 55, 1140, 495),
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            BackColor = Color.FromArgb(3, 12, 18),
            ForeColor = Color.FromArgb(159, 183, 189),
            BorderStyle = BorderStyle.None,
            Font = new Font("Consolas", 9F),
            Text = string.Join(Environment.NewLine, _activityLines)
        };
        logCard.Controls.Add(box);
        _surface.Controls.Add(logCard);

        SetHeaderState("CONCLUÍDO", Accent);
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
            var open = new Button
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

    private void ShowSettingsView()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Idle;
        _nav.Visible = true;
        SetActiveNav(4);

        var settingsBadge = MakeBadge("CONFIGURAÇÕES   ·   VORKEN");
        settingsBadge.Location = new Point(44, 34);
        _surface.Controls.Add(settingsBadge);
        _surface.Controls.Add(MakeLabel(
            "Configurações",
            new Rectangle(44, 80, 600, 56),
            31F,
            TextPrimary,
            FontStyle.Bold));

        var card = MakeCard(new Rectangle(44, 180, 780, 330));
        card.Controls.Add(MakeSectionTitle("SESSÃO E PRIVACIDADE", 20, 20));
        card.Controls.Add(MakeLabel(
            "Modo de análise\nON DEMAND · USER MODE\n\n" +
            "O scanner só executa após consentimento explícito.\n" +
            "Senhas, cookies, mensagens, fotos e documentos pessoais não fazem parte da coleta.",
            new Rectangle(24, 65, 710, 170),
            10.2F,
            TextSecondary));

        var privacy = new Button
        {
            Text = "Política de Privacidade ↗",
            Bounds = new Rectangle(24, 252, 220, 44)
        };
        StyleGhostButton(privacy);
        privacy.Click += (_, _) => OpenUrl(PrivacyUrl);
        card.Controls.Add(privacy);

        var terms = new Button
        {
            Text = "Termos de Uso ↗",
            Bounds = new Rectangle(260, 252, 180, 44)
        };
        StyleGhostButton(terms);
        terms.Click += (_, _) => OpenUrl(TermsUrl);
        card.Controls.Add(terms);

        _surface.Controls.Add(card);
        SetHeaderState("READY", Accent);
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
            BackColor = Color.FromArgb(6, 20, 28),
            BorderColor = Border
        };
    }

    private Label MakeBadge(string text)
    {
        return new Label
        {
            Text = "●  " + text,
            AutoSize = true,
            Padding = new Padding(12, 6, 12, 6),
            BackColor = Color.FromArgb(6, 35, 36),
            ForeColor = Accent,
            Font = new Font("Consolas", 8.2F, FontStyle.Bold)
        };
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
            BackColor = Color.FromArgb(5, 18, 24),
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
            BackColor = Color.FromArgb(5, 18, 24),
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
            BackColor = Color.FromArgb(5, 18, 24),
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
        _headerStatus.BackColor = Color.FromArgb(6, 31, 36);
    }

    private static void StylePrimaryButton(Button button)
    {
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 0;
        button.BackColor = Accent;
        button.ForeColor = Color.FromArgb(1, 26, 29);
        button.Font = new Font("Segoe UI", 12F, FontStyle.Bold);
        button.Cursor = Cursors.Hand;
        button.TabStop = true;

        button.MouseEnter += (_, _) =>
        {
            if (button.Enabled)
                button.BackColor = Color.FromArgb(81, 250, 215);
        };

        button.MouseLeave += (_, _) =>
        {
            if (button.Enabled)
                button.BackColor = Accent;
        };
    }

    private static void StyleGhostButton(Button button)
    {
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderColor = BorderBright;
        button.FlatAppearance.BorderSize = 1;
        button.BackColor = Color.FromArgb(5, 17, 23);
        button.ForeColor = TextPrimary;
        button.Font = new Font("Segoe UI", 8.2F, FontStyle.Bold);
        button.Cursor = Cursors.Hand;
    }

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
            "high" => "ALTO",
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
        if (!_running)
            return;

        DialogResult answer = MessageBox.Show(
            this,
            "A análise ainda está em andamento. Fechar agora pode interromper o envio dos dados. Deseja fechar mesmo assim?",
            "Vorken Anti Cheat",
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

    [DllImport("user32.dll")]
    private static extern bool ReleaseCapture();

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, int wParam, int lParam);
}

internal enum AnimatedSurfaceMode
{
    Idle,
    Scanning,
    Complete,
    Error
}

internal sealed class BorderFrame : Panel
{
    internal Color BorderColor { get; set; } = Color.FromArgb(24, 117, 141);

    internal BorderFrame()
    {
        DoubleBuffered = true;
        Padding = new Padding(1);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        using var pen = new Pen(BorderColor, 1);
        e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
    }
}

internal class BorderedPanel : Panel
{
    internal Color BorderColor { get; set; } = Color.FromArgb(21, 61, 76);

    internal BorderedPanel()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        using var pen = new Pen(BorderColor, 1);
        e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
    }
}

internal sealed class VorkenCard : BorderedPanel
{
}

internal sealed class AnimatedSurface : Panel
{
    internal float Motion { get; set; }
    internal AnimatedSurfaceMode Mode { get; set; }

    internal AnimatedSurface()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
        BackColor = Color.FromArgb(4, 10, 15);
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        using (var background = new LinearGradientBrush(
            ClientRectangle,
            Color.FromArgb(4, 10, 15),
            Color.FromArgb(4, 17, 24),
            LinearGradientMode.Vertical))
        {
            g.FillRectangle(background, ClientRectangle);
        }

        using (var gridPen = new Pen(Color.FromArgb(10, 43, 239, 201), 1))
        {
            const int spacing = 32;

            for (int x = 0; x < Width; x += spacing)
                g.DrawLine(gridPen, x, 0, x, Height);

            for (int y = 0; y < Height; y += spacing)
                g.DrawLine(gridPen, 0, y, Width, y);
        }

        float glowX =
            Width * 0.75f +
            (float)Math.Sin(Motion * 0.45f) * 28f;

        float glowY =
            Height * 0.28f +
            (float)Math.Cos(Motion * 0.32f) * 20f;

        int glowR = Mode == AnimatedSurfaceMode.Error ? 255 : 43;
        int glowG = Mode == AnimatedSurfaceMode.Error ? 72 : 239;
        int glowB = Mode == AnimatedSurfaceMode.Error ? 88 : 201;

        for (int layer = 8; layer >= 1; layer--)
        {
            int size = 92 + (layer * 48);
            int alpha = Math.Max(2, 18 - (layer * 2));

            using var glowBrush =
                new SolidBrush(Color.FromArgb(alpha, glowR, glowG, glowB));

            g.FillEllipse(
                glowBrush,
                glowX - (size / 2f),
                glowY - (size / 2f),
                size,
                size);
        }

        if (Mode == AnimatedSurfaceMode.Scanning)
        {
            float normalized =
                (float)((Math.Sin(Motion * 1.05f) + 1d) / 2d);

            int y =
                (int)(100 + normalized * Math.Max(100, Height - 190));

            using var scanPen =
                new Pen(Color.FromArgb(80, 43, 239, 201), 1);

            g.DrawLine(scanPen, 24, y, Width - 24, y);
        }
    }
}

internal sealed class ScannerPulseControl : Control
{
    private readonly System.Windows.Forms.Timer _timer = new();
    private float _phase;

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

        g.DrawRectangle(borderPen, 0, 0, Width - 1, Height - 1);

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

        using var textBrush = new SolidBrush(Color.FromArgb(43, 239, 201));
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
