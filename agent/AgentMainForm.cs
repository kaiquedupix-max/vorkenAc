using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace Vorken.Agent;

internal sealed class AgentMainForm : Form
{
    private readonly string[] _args;

    private readonly AnimatedSurface _surface = new();
    private readonly Panel _header = new();
    private readonly Label _headerStatus = new();
    private readonly Label _statusTitle = new();
    private readonly Label _statusMessage = new();
    private readonly TextBox _activityBox = new();
    private readonly Panel _progressTrack = new();
    private readonly Panel _progressGlow = new();
    private readonly Button _acceptButton = new();
    private readonly Button _closeButton = new();
    private readonly System.Windows.Forms.Timer _motionTimer = new();

    private bool _running;
    private bool _finished;
    private float _motion;
    private int _progressDirection = 1;

    private static readonly Color Background = Color.FromArgb(5, 9, 12);
    private static readonly Color Surface = Color.FromArgb(9, 18, 22);
    private static readonly Color SurfaceAlt = Color.FromArgb(12, 27, 31);
    private static readonly Color Border = Color.FromArgb(27, 54, 55);
    private static readonly Color Accent = Color.FromArgb(92, 240, 192);
    private static readonly Color AccentSoft = Color.FromArgb(43, 184, 143);
    private static readonly Color TextPrimary = Color.FromArgb(238, 248, 246);
    private static readonly Color TextSecondary = Color.FromArgb(139, 160, 160);
    private static readonly Color TextDim = Color.FromArgb(77, 100, 102);
    private static readonly Color Warning = Color.FromArgb(240, 193, 90);
    private static readonly Color Success = Color.FromArgb(92, 240, 192);
    private static readonly Color Danger = Color.FromArgb(239, 104, 104);

    internal AgentMainForm(string[] args)
    {
        _args = args;

        Text = "Vorken Anti Cheat";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(920, 650);
        MinimumSize = new Size(920, 650);
        MaximumSize = new Size(920, 650);
        BackColor = Background;
        ForeColor = TextPrimary;
        Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        DoubleBuffered = true;

        BuildShell();
        ShowConsentView();

        _motionTimer.Interval = 36;
        _motionTimer.Tick += MotionTimer_Tick;
        _motionTimer.Start();

        FormClosing += OnFormClosing;
    }

    private void BuildShell()
    {
        _header.Dock = DockStyle.Top;
        _header.Height = 82;
        _header.BackColor = Color.FromArgb(7, 14, 17);
        _header.Padding = new Padding(28, 16, 28, 12);

        var brandMark = new Label
        {
            Text = "V",
            AutoSize = false,
            Size = new Size(42, 42),
            Location = new Point(28, 20),
            TextAlign = ContentAlignment.MiddleCenter,
            BackColor = Accent,
            ForeColor = Background,
            Font = new Font("Segoe UI", 18F, FontStyle.Bold)
        };

        var brandName = new Label
        {
            Text = "VORKEN",
            AutoSize = true,
            Location = new Point(84, 20),
            Font = new Font("Segoe UI", 14F, FontStyle.Bold),
            ForeColor = TextPrimary
        };

        var brandCaption = new Label
        {
            Text = "ANTI CHEAT · SECURE SCAN SESSION",
            AutoSize = true,
            Location = new Point(86, 48),
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            ForeColor = AccentSoft
        };

        _headerStatus.Text = "● READY";
        _headerStatus.AutoSize = true;
        _headerStatus.Location = new Point(792, 34);
        _headerStatus.Font = new Font("Consolas", 8F, FontStyle.Bold);
        _headerStatus.ForeColor = Accent;

        var divider = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 1,
            BackColor = Color.FromArgb(20, 42, 43)
        };

        _header.Controls.Add(brandMark);
        _header.Controls.Add(brandName);
        _header.Controls.Add(brandCaption);
        _header.Controls.Add(_headerStatus);
        _header.Controls.Add(divider);

        _surface.Dock = DockStyle.Fill;
        _surface.BackColor = Background;

        Controls.Add(_surface);
        Controls.Add(_header);
    }

    private void ShowConsentView()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Idle;

        var badge = MakeBadge("PLAYER INTEGRITY · EVIDENCE FIRST");
        badge.Location = new Point(48, 42);

        var title = new Label
        {
            Text = "Análise técnica.\nSem ruído desnecessário.",
            AutoSize = true,
            Location = new Point(46, 78),
            Font = new Font("Segoe UI", 29F, FontStyle.Bold),
            ForeColor = TextPrimary,
            BackColor = Color.Transparent
        };

        var description = new Label
        {
            Text = "O Vorken coleta evidências técnicas para revisão anti-cheat.\nA análise só começa depois que você aceitar os termos.",
            AutoSize = true,
            Location = new Point(49, 176),
            MaximumSize = new Size(470, 0),
            Font = new Font("Segoe UI", 10.2F),
            ForeColor = TextSecondary,
            BackColor = Color.Transparent
        };

        var termsCard = MakeCard(new Rectangle(48, 248, 514, 238));
        var termsTitle = new Label
        {
            Text = "O QUE SERÁ ANALISADO",
            AutoSize = true,
            Location = new Point(20, 18),
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = Accent,
            BackColor = Color.Transparent
        };

        var termsText = new Label
        {
            Text =
                "• USB, dispositivos seriais e hardware relacionado\n" +
                "• Prefetch, BAM, Amcache, ShimCache, PCA e USN\n" +
                "• Downloads, origem de arquivos e vestígios do navegador\n" +
                "• Assinaturas digitais, processos e módulos carregados\n" +
                "• Autoruns, integridade do sistema e rede",
            AutoSize = true,
            Location = new Point(21, 53),
            MaximumSize = new Size(468, 0),
            Font = new Font("Segoe UI", 9.2F),
            ForeColor = TextSecondary,
            BackColor = Color.Transparent
        };

        var privacy = new Label
        {
            Text = "PRIVACIDADE  ·  Não coletamos senhas, cookies, mensagens, fotos ou documentos pessoais.",
            AutoSize = false,
            Size = new Size(472, 46),
            Location = new Point(20, 171),
            Padding = new Padding(12, 8, 10, 8),
            BackColor = SurfaceAlt,
            ForeColor = Warning,
            Font = new Font("Segoe UI", 8.4F, FontStyle.Bold)
        };

        termsCard.Controls.Add(termsTitle);
        termsCard.Controls.Add(termsText);
        termsCard.Controls.Add(privacy);

        var sessionCard = MakeCard(new Rectangle(590, 80, 282, 406));

        var sessionLabel = new Label
        {
            Text = "SECURE SESSION",
            AutoSize = true,
            Location = new Point(20, 20),
            Font = new Font("Consolas", 8F, FontStyle.Bold),
            ForeColor = Accent,
            BackColor = Color.Transparent
        };

        var scannerTitle = new Label
        {
            Text = "Vorken Scanner",
            AutoSize = true,
            Location = new Point(20, 51),
            Font = new Font("Segoe UI", 17F, FontStyle.Bold),
            ForeColor = TextPrimary,
            BackColor = Color.Transparent
        };

        var scannerCopy = new Label
        {
            Text = "Coleta iniciada pelo usuário.\nProgresso visível.\nRelatório preparado para revisão.",
            AutoSize = true,
            Location = new Point(21, 88),
            MaximumSize = new Size(232, 0),
            Font = new Font("Segoe UI", 9.2F),
            ForeColor = TextSecondary,
            BackColor = Color.Transparent
        };

        var pulse = new ScannerPulseControl
        {
            Location = new Point(20, 160),
            Size = new Size(242, 116),
            BackColor = Color.FromArgb(5, 12, 15)
        };

        var featureA = MakeMiniStatus("MODE", "ON DEMAND", 20, 294);
        var featureB = MakeMiniStatus("DRIVER", "USER MODE", 142, 294);

        sessionCard.Controls.Add(sessionLabel);
        sessionCard.Controls.Add(scannerTitle);
        sessionCard.Controls.Add(scannerCopy);
        sessionCard.Controls.Add(pulse);
        sessionCard.Controls.Add(featureA);
        sessionCard.Controls.Add(featureB);

        _acceptButton.Text = "ACEITAR E INICIAR  →";
        StylePrimaryButton(_acceptButton);
        _acceptButton.Location = new Point(48, 510);
        _acceptButton.Size = new Size(260, 48);
        _acceptButton.Click -= AcceptButton_Click;
        _acceptButton.Click += AcceptButton_Click;

        var cancelButton = new Button
        {
            Text = "FECHAR",
            Location = new Point(321, 510),
            Size = new Size(112, 48)
        };
        StyleGhostButton(cancelButton);
        cancelButton.Click += (_, _) => Close();

        var consent = new Label
        {
            Text = "Ao aceitar, você autoriza esta coleta técnica para a análise solicitada.",
            AutoSize = true,
            Location = new Point(48, 572),
            Font = new Font("Segoe UI", 8F),
            ForeColor = TextDim,
            BackColor = Color.Transparent
        };

        _surface.Controls.Add(badge);
        _surface.Controls.Add(title);
        _surface.Controls.Add(description);
        _surface.Controls.Add(termsCard);
        _surface.Controls.Add(sessionCard);
        _surface.Controls.Add(_acceptButton);
        _surface.Controls.Add(cancelButton);
        _surface.Controls.Add(consent);

        _headerStatus.Text = "● READY";
        _headerStatus.ForeColor = Accent;
    }

    private async void AcceptButton_Click(object? sender, EventArgs e)
    {
        if (_running)
            return;

        _running = true;
        _finished = false;

        ShowProgressView();
        AppendStatus("Termos aceitos. Preparando a análise...");

        int result;

        try
        {
            result = await Task.Run(
                () => Program.RunAnalysisAsync(_args, AppendStatus));
        }
        catch (Exception ex)
        {
            AppendStatus("Falha inesperada: " + ex.Message);
            result = 1;
        }

        _running = false;
        _finished = true;

        ShowCompletion(result == 0);
    }

    private void ShowProgressView()
    {
        _surface.Controls.Clear();
        _surface.Mode = AnimatedSurfaceMode.Scanning;

        var badge = MakeBadge("LIVE SCAN · SECURE SESSION");
        badge.Location = new Point(48, 40);

        _statusTitle.Text = "Análise em andamento";
        _statusTitle.AutoSize = true;
        _statusTitle.Location = new Point(46, 78);
        _statusTitle.Font = new Font("Segoe UI", 28F, FontStyle.Bold);
        _statusTitle.ForeColor = TextPrimary;
        _statusTitle.BackColor = Color.Transparent;

        _statusMessage.Text = "Não feche esta janela enquanto a coleta estiver em andamento.";
        _statusMessage.AutoSize = true;
        _statusMessage.Location = new Point(49, 128);
        _statusMessage.Font = new Font("Segoe UI", 10F);
        _statusMessage.ForeColor = TextSecondary;
        _statusMessage.BackColor = Color.Transparent;

        _progressTrack.Location = new Point(48, 171);
        _progressTrack.Size = new Size(824, 6);
        _progressTrack.BackColor = Color.FromArgb(18, 40, 42);

        _progressGlow.Location = new Point(0, 0);
        _progressGlow.Size = new Size(155, 6);
        _progressGlow.BackColor = Accent;
        _progressTrack.Controls.Clear();
        _progressTrack.Controls.Add(_progressGlow);

        var consoleCard = MakeCard(new Rectangle(48, 206, 824, 318));

        var consoleTitle = new Label
        {
            Text = "EVIDENCE STREAM",
            AutoSize = true,
            Location = new Point(18, 15),
            Font = new Font("Consolas", 8F, FontStyle.Bold),
            ForeColor = Accent,
            BackColor = Color.Transparent
        };

        var consoleState = new Label
        {
            Text = "●  TELEMETRY ACTIVE",
            AutoSize = true,
            Location = new Point(650, 15),
            Font = new Font("Consolas", 8F, FontStyle.Bold),
            ForeColor = AccentSoft,
            BackColor = Color.Transparent
        };

        _activityBox.Location = new Point(18, 47);
        _activityBox.Size = new Size(788, 250);
        _activityBox.Multiline = true;
        _activityBox.ReadOnly = true;
        _activityBox.ScrollBars = ScrollBars.Vertical;
        _activityBox.BackColor = Color.FromArgb(4, 10, 12);
        _activityBox.ForeColor = Color.FromArgb(135, 161, 159);
        _activityBox.BorderStyle = BorderStyle.FixedSingle;
        _activityBox.Font = new Font("Consolas", 9F);
        _activityBox.Clear();

        consoleCard.Controls.Add(consoleTitle);
        consoleCard.Controls.Add(consoleState);
        consoleCard.Controls.Add(_activityBox);

        var footerStatus = new Label
        {
            Text = "A janela permanecerá aberta quando o envio terminar.",
            AutoSize = true,
            Location = new Point(49, 548),
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            ForeColor = AccentSoft,
            BackColor = Color.Transparent
        };

        _surface.Controls.Add(badge);
        _surface.Controls.Add(_statusTitle);
        _surface.Controls.Add(_statusMessage);
        _surface.Controls.Add(_progressTrack);
        _surface.Controls.Add(consoleCard);
        _surface.Controls.Add(footerStatus);

        _headerStatus.Text = "● SCANNING";
        _headerStatus.ForeColor = Accent;
    }

    private void ShowCompletion(bool success)
    {
        if (InvokeRequired)
        {
            BeginInvoke((Action)(() => ShowCompletion(success)));
            return;
        }

        _surface.Mode = success
            ? AnimatedSurfaceMode.Complete
            : AnimatedSurfaceMode.Error;

        _progressGlow.Location = Point.Empty;
        _progressGlow.Size = _progressTrack.Size;
        _progressGlow.BackColor = success ? Success : Danger;

        _statusTitle.Text = success
            ? "Dados enviados para análise"
            : "Não foi possível concluir o envio";

        _statusTitle.ForeColor = success ? Success : Danger;

        _statusMessage.Text = success
            ? "A coleta foi concluída e os dados foram enviados para o responsável analisar.\nEsta janela não será fechada automaticamente."
            : "A análise foi interrompida antes de concluir o envio. Consulte a atividade abaixo.";

        _headerStatus.Text = success ? "● SENT" : "● ERROR";
        _headerStatus.ForeColor = success ? Success : Danger;

        _closeButton.Text = "FECHAR";
        _closeButton.Location = new Point(48, 578);
        _closeButton.Size = new Size(150, 42);
        StylePrimaryButton(_closeButton);
        _closeButton.BackColor = success ? Accent : Danger;
        _closeButton.Click -= CloseButton_Click;
        _closeButton.Click += CloseButton_Click;

        if (!_surface.Controls.Contains(_closeButton))
            _surface.Controls.Add(_closeButton);
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
        string prefix =
            normalized.StartsWith("✓", StringComparison.Ordinal)
                ? "[OK]"
                : normalized.StartsWith("!", StringComparison.Ordinal)
                    ? "[WARN]"
                    : normalized.Contains("Falha", StringComparison.OrdinalIgnoreCase)
                        ? "[ERR]"
                        : "[INFO]";

        string line =
            $"[{DateTime.Now:HH:mm:ss}] {prefix} {normalized}{Environment.NewLine}";

        _activityBox.AppendText(line);
        _activityBox.SelectionStart = _activityBox.TextLength;
        _activityBox.ScrollToCaret();
    }

    private void MotionTimer_Tick(object? sender, EventArgs e)
    {
        _motion += 0.055f;
        if (_motion > 10000f)
            _motion = 0f;

        _surface.Motion = _motion;
        _surface.Invalidate();

        if (_running && _progressTrack.Controls.Contains(_progressGlow))
        {
            int maxX = Math.Max(0, _progressTrack.Width - _progressGlow.Width);

            if (_progressGlow.Left >= maxX)
                _progressDirection = -1;
            else if (_progressGlow.Left <= 0)
                _progressDirection = 1;

            _progressGlow.Left =
                Math.Max(0, Math.Min(maxX, _progressGlow.Left + (7 * _progressDirection)));
        }

        if (((int)(_motion * 10)) % 12 == 0)
        {
            _headerStatus.ForeColor =
                _headerStatus.ForeColor == Accent
                    ? Color.FromArgb(77, 180, 151)
                    : Accent;
        }
    }

    private static Panel MakeCard(Rectangle bounds)
    {
        return new Panel
        {
            Bounds = bounds,
            BackColor = Color.FromArgb(9, 20, 24),
            Padding = new Padding(1),
            BorderStyle = BorderStyle.FixedSingle
        };
    }

    private static Label MakeBadge(string text)
    {
        return new Label
        {
            Text = "●  " + text,
            AutoSize = true,
            Padding = new Padding(10, 7, 10, 7),
            BackColor = Color.FromArgb(8, 26, 23),
            ForeColor = Accent,
            Font = new Font("Consolas", 8F, FontStyle.Bold)
        };
    }

    private static Panel MakeMiniStatus(string label, string value, int x, int y)
    {
        var panel = new Panel
        {
            Location = new Point(x, y),
            Size = new Size(120, 72),
            BackColor = Color.FromArgb(7, 16, 19),
            BorderStyle = BorderStyle.FixedSingle
        };

        panel.Controls.Add(new Label
        {
            Text = label,
            AutoSize = true,
            Location = new Point(10, 10),
            Font = new Font("Consolas", 7F, FontStyle.Bold),
            ForeColor = TextDim,
            BackColor = Color.Transparent
        });

        panel.Controls.Add(new Label
        {
            Text = value,
            AutoSize = true,
            Location = new Point(10, 35),
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            ForeColor = TextPrimary,
            BackColor = Color.Transparent
        });

        return panel;
    }

    private static void StylePrimaryButton(Button button)
    {
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 0;
        button.BackColor = Accent;
        button.ForeColor = Background;
        button.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
        button.Cursor = Cursors.Hand;
        button.TabStop = true;

        button.MouseEnter += (_, _) =>
        {
            if (button.Enabled)
                button.BackColor = Color.FromArgb(116, 248, 207);
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
        button.FlatAppearance.BorderColor = Border;
        button.FlatAppearance.BorderSize = 1;
        button.BackColor = Color.FromArgb(7, 15, 18);
        button.ForeColor = TextSecondary;
        button.Font = new Font("Segoe UI", 8.5F, FontStyle.Bold);
        button.Cursor = Cursors.Hand;

        button.MouseEnter += (_, _) =>
        {
            button.FlatAppearance.BorderColor = AccentSoft;
            button.ForeColor = TextPrimary;
        };

        button.MouseLeave += (_, _) =>
        {
            button.FlatAppearance.BorderColor = Border;
            button.ForeColor = TextSecondary;
        };
    }

    private void CloseButton_Click(object? sender, EventArgs e) => Close();

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
}

internal enum AnimatedSurfaceMode
{
    Idle,
    Scanning,
    Complete,
    Error
}

internal sealed class AnimatedSurface : Panel
{
    internal float Motion { get; set; }
    internal AnimatedSurfaceMode Mode { get; set; }

    internal AnimatedSurface()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
        BackColor = Color.FromArgb(5, 9, 12);
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        using (var background = new LinearGradientBrush(
            ClientRectangle,
            Color.FromArgb(5, 9, 12),
            Color.FromArgb(6, 15, 18),
            LinearGradientMode.Vertical))
        {
            g.FillRectangle(background, ClientRectangle);
        }

        using (var gridPen = new Pen(Color.FromArgb(10, 92, 240, 192), 1))
        {
            const int spacing = 38;

            for (int x = 0; x < Width; x += spacing)
                g.DrawLine(gridPen, x, 0, x, Height);

            for (int y = 0; y < Height; y += spacing)
                g.DrawLine(gridPen, 0, y, Width, y);
        }

        float glowX =
            Width * 0.73f +
            (float)Math.Sin(Motion * 0.45f) * 35f;

        float glowY =
            Height * 0.28f +
            (float)Math.Cos(Motion * 0.32f) * 24f;

        using (var path = new GraphicsPath())
        {
            path.AddEllipse(glowX - 170, glowY - 170, 340, 340);

            using var glow = new PathGradientBrush(path)
            {
                CenterColor = Color.FromArgb(
                    Mode == AnimatedSurfaceMode.Error ? 28 : 34,
                    Mode == AnimatedSurfaceMode.Error ? 239 : 92,
                    Mode == AnimatedSurfaceMode.Error ? 104 : 240,
                    Mode == AnimatedSurfaceMode.Error ? 104 : 192),
                SurroundColors = new[] { Color.Transparent }
            };

            g.FillEllipse(glow, glowX - 170, glowY - 170, 340, 340);
        }

        if (Mode == AnimatedSurfaceMode.Scanning)
        {
            float normalized =
                (float)((Math.Sin(Motion * 1.05f) + 1d) / 2d);

            int y =
                (int)(110 + normalized * Math.Max(80, Height - 220));

            using var scanPen =
                new Pen(Color.FromArgb(115, 92, 240, 192), 1);

            g.DrawLine(scanPen, 28, y, Width - 28, y);
        }

        base.OnPaintBackground(e);
    }
}

internal sealed class ScannerPulseControl : Control
{
    private readonly System.Windows.Forms.Timer _timer = new();
    private float _phase;

    internal ScannerPulseControl()
    {
        DoubleBuffered = true;

        _timer.Interval = 40;
        _timer.Tick += (_, _) =>
        {
            _phase += 0.05f;
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

        using var borderPen = new Pen(Color.FromArgb(28, 92, 240, 192), 1);
        using var gridPen = new Pen(Color.FromArgb(12, 92, 240, 192), 1);

        for (int x = 0; x < Width; x += 20)
            g.DrawLine(gridPen, x, 0, x, Height);

        for (int y = 0; y < Height; y += 20)
            g.DrawLine(gridPen, 0, y, Width, y);

        g.DrawRectangle(borderPen, 0, 0, Width - 1, Height - 1);

        float pulse =
            (float)((Math.Sin(_phase * 1.3f) + 1d) / 2d);

        int radius = 18 + (int)(pulse * 18);
        int cx = Width / 2;
        int cy = Height / 2;

        using var outer = new Pen(
            Color.FromArgb(40 + (int)(pulse * 45), 92, 240, 192),
            1);

        using var inner = new SolidBrush(
            Color.FromArgb(130 + (int)(pulse * 80), 92, 240, 192));

        g.DrawEllipse(outer, cx - radius, cy - radius, radius * 2, radius * 2);
        g.FillEllipse(inner, cx - 4, cy - 4, 8, 8);

        using var textBrush = new SolidBrush(Color.FromArgb(111, 151, 149));
        using var font = new Font("Consolas", 7.5F, FontStyle.Bold);

        g.DrawString("READY TO SCAN", font, textBrush, 12, Height - 24);
    }
}
