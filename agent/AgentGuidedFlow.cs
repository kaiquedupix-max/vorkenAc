using System.Drawing;
using System.Windows.Forms;

namespace Vorken.Agent;

internal sealed partial class AgentMainForm
{
    private static Image LoadBrandMark()
    {
        using var stream = typeof(AgentMainForm).Assembly.GetManifestResourceStream("Vorken.BrandMark.png");
        if (stream is null) return SystemIcons.Application.ToBitmap();
        using var image = Image.FromStream(stream); return new Bitmap(image);
    }
    private TableLayoutPanel? _guidedChecks;
    private readonly GuidedStep[] _guidedStages = new GuidedStep[7];
    private bool _guidedCollectionFinished;

    private void ShowProgressView() => ShowGuidedFlow(null);

    private void ShowResultsView(AgentRunResult result)
    {
        if (InvokeRequired) { BeginInvoke((Action)(() => ShowResultsView(result))); return; }
        ShowGuidedFlow(result);
        if (result.ExitCode == 0) _clientResultPollTimer.Start();
        else _clientResultPollTimer.Stop();
    }

    private void ShowGuidedFlow(AgentRunResult? result)
    {
        _surface.SuspendLayout();
        _surface.Controls.Clear();
        _surface.AutoScroll = true;
        _guidedCollectionFinished = false;
        _stepStateLabels.Clear();
        bool complete = result?.ExitCode == 0;
        bool collected = complete || _activityLines.Any(line => line.Contains("Preparando o relatório completo", StringComparison.OrdinalIgnoreCase) || line.Contains("Preparando el informe completo", StringComparison.OrdinalIgnoreCase) || line.Contains("Preparing the complete report", StringComparison.OrdinalIgnoreCase));
        _surface.Mode = result is null ? AnimatedSurfaceMode.Scanning : complete ? AnimatedSurfaceMode.Complete : AnimatedSurfaceMode.Error;
        _nav.Visible = true;
        _nav.Enabled = result is not null;
        _headerStatus.Visible = false;
        SetActiveNav(1);

        var root = new GuidedGrid { Dock = DockStyle.Fill, Padding = new Padding(14), BackColor = Surface, ColumnCount = 1, RowCount = 2 };
        var frame = new Panel { Dock = DockStyle.Fill, Padding = new Padding(24, 18, 24, 22), BackColor = Background };
        frame.Controls.Add(root);
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 134));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var title = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, ColumnCount = 1, BackColor = Color.Transparent };
        title.RowStyles.Add(new RowStyle(SizeType.Absolute, 62));
        title.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        title.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        string heading = result is null ? L("Verificação em andamento", "Verificación en curso", "Verification in progress") : collected ? L("Coleta finalizada", "Recopilación finalizada", "Collection completed") : L("Análise interrompida", "Análisis interrumpido", "Analysis interrupted");
        var headingRow = new FlowLayoutPanel { AutoSize = true, Anchor = AnchorStyles.None, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
        var headline = GuidedLabel(heading, 32, TextPrimary, FontStyle.Bold); headline.Dock = DockStyle.None; headline.AutoSize = true; headline.Margin = new Padding(0, 0, 16, 0); headingRow.Controls.Add(headline);
        if (result is not null) { var chip = new Label { Text = complete ? L("✓ Enviado", "✓ Enviado", "✓ Uploaded") : collected ? L("◷ Envio pendente", "◷ Envío pendiente", "◷ Upload pending") : L("! Interrompida", "! Interrumpido", "! Interrupted"), AutoSize = true, BackColor = complete ? Success : Warning, ForeColor = Background, Padding = new Padding(12, 7, 12, 7), Margin = new Padding(0, 7, 0, 0), Font = new Font("Segoe UI", 11, FontStyle.Bold) }; headingRow.Controls.Add(chip); }
        title.Controls.Add(headingRow, 0, 0);
        title.Controls.Add(GuidedLabel(result is null ? L("Acompanhe cada verificação e os registros em tempo real.", "Siga cada verificación y sus registros en tiempo real.", "Follow each check and its logs in real time.") : complete ? L("Dados enviados. Consulte o resultado conforme a liberação administrativa.", "Datos enviados. Consulte el resultado según la autorización administrativa.", "Data sent. Results follow administrative release.") : L("A verificação não foi concluída. Consulte o erro antes de tentar novamente.", "La verificación no finalizó. Revise el error antes de reintentar.", "Verification did not complete. Review the error before retrying."), 10, TextSecondary), 0, 1);
        title.Controls.Add(GuidedLabel(L("Etapa concluída não significa ausência de achados.", "Una etapa completada no significa ausencia de hallazgos.", "A completed step does not imply absence of findings."), 11, TextSecondary), 0, 2);
        foreach (var label in title.Controls.OfType<Label>()) { label.TextAlign = ContentAlignment.MiddleCenter; if (title.GetRow(label)==1) label.Font = new Font("Segoe UI", 13); }
        root.Controls.Add(title, 0, 0);

        var workspace = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = Color.Transparent, Padding = Padding.Empty, ColumnCount = 2, RowCount = 1 };
        workspace.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
        workspace.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68));
        var steps = new GuidedGrid { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 1, Padding = new Padding(12), Margin = new Padding(0, 0, 12, 0), BackColor = Background };
        _guidedChecks = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7, BackColor = Background };
        string[] stageTitles = { L("Sessão validada", "Sesión validada", "Session validated"), L("Integridade do sistema", "Integridad del sistema", "System integrity"), L("Histórico de execução", "Historial de ejecución", "Execution history"), L("Dispositivos USB", "Dispositivos USB", "USB devices"), L("Downloads e origem", "Descargas y origen", "Downloads and origin"), L("Processos e módulos", "Procesos y módulos", "Processes and modules"), L("Envio do relatório", "Envío del informe", "Report upload") };
        string[] stageHints = { L("Verificação da sessão do jogador", "Verificación de la sesión", "Player session verification"), L("Verificação de arquivos e drivers", "Verificación de archivos y drivers", "File and driver verification"), L("Análise de atividades recentes", "Análisis de actividades recientes", "Recent activity analysis"), L("Enumeração de dispositivos conectados", "Dispositivos conectados", "Connected device enumeration"), L("Verificação de arquivos obtidos", "Verificación de archivos obtenidos", "Downloaded file verification"), L("Análise de processos em execução", "Procesos en ejecución", "Running process analysis"), L("Compressão e envio para o servidor", "Compresión y envío al servidor", "Compression and server upload") };
        for (int i = 0; i < 7; i++)
        {
            _guidedChecks.RowStyles.Add(new RowStyle(SizeType.Percent, 100F / 7));
            _guidedStages[i] = new GuidedStep { Dock = DockStyle.Fill, Number = i + 1, Title = stageTitles[i], Hint = stageHints[i], BackColor = Background, Margin = Padding.Empty };
            _guidedChecks.Controls.Add(_guidedStages[i], 0, i);
        }
        steps.Controls.Add(_guidedChecks); workspace.Controls.Add(steps, 0, 0);

        var content = new GuidedGrid { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(12), BackColor = Background };
        content.RowStyles.Add(new RowStyle(SizeType.Absolute, 82));
        content.RowStyles.Add(new RowStyle(SizeType.Absolute, result is null ? 34 : 8));
        content.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        content.RowStyles.Add(new RowStyle(SizeType.Absolute, 88));
        content.RowStyles.Add(new RowStyle(SizeType.Absolute, 98));
        content.RowStyles.Add(new RowStyle(SizeType.Absolute, 76));
        var metrics = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Color.Transparent, Margin = Padding.Empty };
        metrics.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        foreach (var pair in new[] { (_elapsedLabel, L("Tempo decorrido", "Tiempo transcurrido", "Elapsed time")), (_artifactCountLabel, L("Artefatos coletados", "Artefactos recopilados", "Collected artifacts")), (_deviceCountLabel, L("Dispositivos", "Dispositivos", "Devices")) })
        {
            metrics.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.333F));
            var metric = new GuidedGrid { Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 2, Margin = new Padding(0, 0, 12, 8), BackColor = SurfaceAlt, Padding = new Padding(10, 4, 10, 4) };
            metric.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 48)); metric.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            metric.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
            metric.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            metric.Controls.Add(new GuidedIcon { Dock = DockStyle.Fill, Kind = pair.Item1 == _elapsedLabel ? 0 : pair.Item1 == _artifactCountLabel ? 1 : 2 }, 0, 0); metric.SetRowSpan(metric.GetControlFromPosition(0, 0)!, 2);
            metric.Controls.Add(GuidedLabel(pair.Item2, 11F, TextSecondary), 1, 0);
            pair.Item1.Dock = DockStyle.Fill; pair.Item1.ForeColor = TextPrimary; pair.Item1.Font = new Font("Segoe UI", 18, FontStyle.Bold); pair.Item1.BackColor = Color.Transparent;
            metric.Controls.Add(pair.Item1, 1, 1); metrics.Controls.Add(metric);
        }
        _artifactCountLabel.Text = $"{_artifactCount:N0}";
        _deviceCountLabel.Text = $"{_devicesSeen:N0}";
        if (_scanStartedAt != default) _elapsedLabel.Text = (DateTime.Now - _scanStartedAt).ToString(@"mm\:ss");
        else _elapsedLabel.Text = "00:00";
        content.Controls.Add(metrics, 0, 0);
        var progress = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2 };
        progress.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); progress.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 84));
        _progressEtaLabel.Dock = DockStyle.Fill; _progressEtaLabel.ForeColor = TextSecondary; _progressEtaLabel.AutoEllipsis = true;
        _progressEtaLabel.Text = result is null ? L("Progresso estimado", "Progreso estimado", "Estimated progress") : complete ? L("Envio concluído", "Envío completado", "Upload completed") : L("Não concluído", "No finalizado", "Not completed");
        _progressPercentLabel.Dock = DockStyle.Fill; _progressPercentLabel.ForeColor = Blue;
        progress.Controls.Add(_progressEtaLabel, 0, 0); progress.Controls.Add(_progressPercentLabel, 1, 0);
        _progressTrack.Dock = DockStyle.Fill; _progressTrack.BackColor = Border; _progressTrack.Margin = new Padding(0, 7, 0, 8);
        _progressFill.Dock = DockStyle.None; _progressFill.Location = Point.Empty; _progressFill.Height = 12; _progressFill.BackColor = complete ? Success : Accent;
        _progressTrack.Controls.Add(_progressFill); progress.Controls.Add(_progressTrack, 0, 1); progress.SetColumnSpan(_progressTrack, 2);
        _progressTrack.SizeChanged += (_, _) => UpdateProgressUi();
        progress.Visible = result is null; content.Controls.Add(progress, 0, 1);
        _activityBox.Dock = DockStyle.Fill; _activityBox.ReadOnly = true; _activityBox.BorderStyle = BorderStyle.None; _activityBox.BackColor = Background; _activityBox.ForeColor = TextSecondary; _activityBox.Font = new Font("Consolas", 11F); _activityBox.WordWrap = true; _activityBox.ScrollBars = RichTextBoxScrollBars.Vertical;
        _activityBox.Clear(); foreach (string line in _activityLines) AppendColoredActivityLine(line);
        _activityBox.SelectionStart = _activityBox.TextLength; _activityBox.ScrollToCaret();
        var log = new GuidedGrid { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(12), BackColor = Background };
        log.RowStyles.Add(new RowStyle(SizeType.Absolute, 34)); log.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        log.Controls.Add(GuidedLabel(L("▤  Registro de atividade", "▤  Registro de actividad", "▤  Activity log"), 11, TextPrimary, FontStyle.Bold), 0, 0);
        log.Controls.Add(new GuidedLogHost(_activityBox) { Dock = DockStyle.Fill }, 0, 1); content.Controls.Add(log, 0, 2);
        var usbNotice = new GuidedNotice { Dock = DockStyle.Fill, Title = L("Dispositivos USB · Consulte os detalhes na revisão.", "Dispositivos USB · Consulte los detalles.", "USB devices · Review the details."), Description = L("A presença de dispositivos USB, por si só, não é evidência de trapaça.", "La presencia de dispositivos USB no es evidencia de trampas.", "USB presence alone is not evidence of cheating."), Margin = new Padding(0, 8, 0, 3) };
        content.Controls.Add(usbNotice, 0, 3);
        string state = result is null ? L("● ANÁLISE ATIVA — mantenha o programa aberto.", "● ANÁLISIS ACTIVO — mantenga el programa abierto.", "● ANALYSIS ACTIVE — keep the program open.") : complete ? L("✓ ENVIO CONCLUÍDO — resultado disponível conforme liberação.", "✓ ENVÍO COMPLETADO — resultado según autorización.", "✓ UPLOAD COMPLETED — results subject to release.") : "! " + (string.IsNullOrWhiteSpace(result.Error) ? L("Falha ao concluir a análise. Consulte os registros.", "Error al finalizar el análisis. Consulte los registros.", "Analysis failed to complete. Review the logs.") : result.Error);
        var notice = new GuidedNotice { Dock = DockStyle.Fill, Failure = result is not null && !complete, Title = result is null ? L("Verificação em andamento", "Verificación en curso", "Verification in progress") : complete ? L("Relatório enviado", "Informe enviado", "Report uploaded") : collected ? L("Falha no envio do relatório", "Error al enviar el informe", "Report upload failed") : L("Análise interrompida", "Análisis interrumpido", "Analysis interrupted"), Description = state, Margin = new Padding(0, 6, 0, 0) }; content.Controls.Add(notice, 0, 4);
        workspace.Controls.Add(content, 1, 0); root.Controls.Add(workspace, 0, 1);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false, Padding = new Padding(0, 12, 0, 0), BackColor = Color.Transparent };
        if (result is not null)
        {
            actions.Controls.Add(GuidedButton(L("Fechar", "Cerrar", "Close"), Close, false));
            if (complete) actions.Controls.Add(GuidedButton(L("Ver resultados", "Ver resultados", "View results"), () => ShowDetailedResultsView(result), false));
            if (!complete) actions.Controls.Add(GuidedButton(L("Tentar novamente", "Reintentar", "Retry"), ShowConsentView, true));
        }
        var copyLog = GuidedButton(L("Copiar log", "Copiar registro", "Copy log"), () => { if (_activityLines.Count > 0) Clipboard.SetText(string.Join(Environment.NewLine, _activityLines)); }, false);
        actions.Controls.Add(copyLog);
        if (result is not null && !complete) actions.Controls.SetChildIndex(copyLog, 1);
        content.Controls.Add(actions, 0, 5); _surface.Controls.Add(frame);
        foreach (string line in _activityLines) UpdateGuidedCheck(line);
        if (result is not null) { _guidedStages[6].State = complete ? 2 : -1; _guidedStages[6].Invalidate(); }
        if (complete) _progressPercent = 100;
        UpdateProgressUi();
        SetHeaderState(result is null ? L("ANALISANDO", "ANALIZANDO", "SCANNING") : complete ? L("CONCLUÍDO", "COMPLETADO", "COMPLETED") : L("INTERROMPIDO", "INTERRUMPIDO", "INTERRUPTED"), complete ? Success : result is null ? Blue : Danger);
        _surface.ResumeLayout(true);
    }

    private Label GuidedLabel(string text, float size, Color color, FontStyle style = FontStyle.Regular) => new() { Text = text, Dock = DockStyle.Fill, ForeColor = color, BackColor = Color.Transparent, Font = new Font("Segoe UI", size, style), TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true, Margin = Padding.Empty };

    private Button GuidedButton(string text, Action action, bool primary)
    {
        var button = new GuidedActionButton { Text = text, Primary = primary, Size = new Size(primary ? 195 : 158, 48), Margin = new Padding(10, 0, 0, 0), FlatStyle = FlatStyle.Flat, BackColor = Background, ForeColor = TextPrimary, Cursor = Cursors.Hand, Font = new Font("Segoe UI", 11, FontStyle.Bold) };
        button.Click += (_, _) => action(); return button;
    }

    private void UpdateGuidedCheck(string line)
    {
        if (_guidedChecks is null || _guidedChecks.IsDisposed) return;
        string lower = line.ToLowerInvariant();
        bool ok = lower.Contains("[ok]"); bool warn = lower.Contains("[warn]");
        bool collecting = lower.Contains("configuração recebida") || lower.Contains("configuración recibida") || lower.Contains("configuration received");
        bool uploading = lower.Contains("preparando o relatório completo") || lower.Contains("preparando el informe completo") || lower.Contains("preparing the complete report");
        bool uploaded = lower.Contains("dados enviados") || lower.Contains("datos enviados") || lower.Contains("data uploaded") || lower.Contains("data successfully submitted");
        if (collecting) _guidedStages[0].State = 2;
        if (uploading || uploaded)
        {
            _guidedCollectionFinished = true;
            for (int i = 0; i < 6; i++) if (_guidedStages[i].State != -1) _guidedStages[i].State = 2;
            _guidedStages[6].State = uploaded ? 2 : 1;
        }
        if (ok || warn)
        {
            int group = lower.Contains("sessão") ? 0 : lower.Contains("usb") || lower.Contains("serial") ? 3 : lower.Contains("download") || lower.Contains("zone") || lower.Contains("navegador") ? 4 : lower.Contains("process") || lower.Contains("módulo") || lower.Contains("memória") ? 5 : lower.Contains("prefetch") || lower.Contains("bam") || lower.Contains("amcache") || lower.Contains("shimcache") || lower.Contains("execução") || lower.Contains("userassist") ? 2 : 1;
            if (warn) _guidedStages[group].State = -1;
            else if (_guidedStages[group].State != -1) _guidedStages[group].State = group == 0 || _guidedCollectionFinished ? 2 : 1;
        }
        foreach (var step in _guidedStages) step?.Invalidate();
    }
}

internal sealed class GuidedGrid : TableLayoutPanel
{
    internal Color LineColor { get; set; } = Color.FromArgb(35, 61, 88);
    internal GuidedGrid() { DoubleBuffered = true; ResizeRedraw = true; }
    protected override void OnPaintBackground(PaintEventArgs e)
    {
        if (Width < 2 || Height < 2) return;
        GuidedBackground.Paint(this, e.Graphics);
        Color top = BackColor.R > 35 ? Color.FromArgb(47, 31, 40) : Color.FromArgb(12, 29, 47);
        Color bottom = BackColor.R > 35 ? Color.FromArgb(34, 24, 32) : Color.FromArgb(6, 18, 29);
        using var fill = new System.Drawing.Drawing2D.LinearGradientBrush(ClientRectangle, top, bottom, 28F);
        using var path = VorkenGeometry.CreateRoundedRectangle(new Rectangle(0, 0, Width - 1, Height - 1), 9);
        e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        e.Graphics.FillPath(fill, path);
    }
    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e); if (Width < 2 || Height < 2) return;
        var previous = Region; Region = null; previous?.Dispose();
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e); if (Width < 2 || Height < 2) return;
        e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using var path = VorkenGeometry.CreateRoundedRectangle(new Rectangle(0, 0, Width - 1, Height - 1), 9);
        using var pen = new Pen(LineColor); e.Graphics.DrawPath(pen, path);
    }
}

internal sealed class GuidedIcon : Control
{
    internal int Kind { get; set; }
    internal GuidedIcon() { SetStyle(ControlStyles.SupportsTransparentBackColor, true); DoubleBuffered = true; BackColor = Color.Transparent; }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e); var g = e.Graphics; g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using var pen = new Pen(Color.FromArgb(87, 168, 255), 2);
        g.TranslateTransform(Math.Max(0, (Width - 30) / 2), Math.Max(0, (Height - 34) / 2));
        if (Kind == 0) { g.DrawEllipse(pen, 1, 3, 28, 28); g.DrawLines(pen, new[] { new Point(15, 8), new Point(15, 18), new Point(22, 18) }); }
        else if (Kind == 1) { g.DrawPolygon(pen, new[] { new Point(6, 1), new Point(20, 1), new Point(28, 9), new Point(28, 32), new Point(6, 32) }); g.DrawLines(pen, new[] { new Point(20, 1), new Point(20, 10), new Point(28, 10) }); g.DrawLine(pen, 11, 18, 23, 18); g.DrawLine(pen, 11, 24, 23, 24); }
        else { g.DrawRectangle(pen, 9, 1, 13, 10); g.DrawRectangle(pen, 5, 11, 21, 21); g.DrawLine(pen, 13, 4, 13, 8); g.DrawLine(pen, 18, 4, 18, 8); }
    }
}

internal sealed class GuidedStep : Control
{
    internal int Number { get; set; }
    internal string Title { get; set; } = "";
    internal string Hint { get; set; } = "";
    internal int State { get; set; }
    internal GuidedStep() { DoubleBuffered = true; ResizeRedraw = true; }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics; g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        Color muted = Color.FromArgb(159, 185, 218), white = Color.FromArgb(237, 243, 255);
        Color color = State == -1 ? Color.FromArgb(255, 112, 101) : State == 2 ? Color.FromArgb(66, 231, 177) : Color.FromArgb(83, 164, 255);
        int cy = Height / 2; using var line = new Pen(Color.FromArgb(54, 93, 131));
        if (Number < 7) g.DrawLine(line, 17, cy + 17, 17, Height);
        if (Number > 1) g.DrawLine(line, 17, 0, 17, cy - 17);
        using var ring = new Pen(State == -1 ? color : Color.FromArgb(75, 139, 210), 2); g.DrawEllipse(ring, 2, cy - 15, 30, 30);
        using var numberFont = new Font("Segoe UI", 10, FontStyle.Bold);
        TextRenderer.DrawText(g, Number.ToString(), numberFont, new Rectangle(2, cy - 15, 30, 30), white, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        int stateWidth = Math.Min(100, Width / 3), textWidth = Math.Max(50, Width - 56 - stateWidth);
        using var titleFont = new Font("Segoe UI", 12, FontStyle.Bold); using var hintFont = new Font("Segoe UI", 9.5F);
        TextRenderer.DrawText(g, Title, titleFont, new Rectangle(48, cy - 23, textWidth, 25), white, TextFormatFlags.EndEllipsis | TextFormatFlags.VerticalCenter);
        TextRenderer.DrawText(g, Hint, hintFont, new Rectangle(48, cy + 3, Width - 58, 23), muted, TextFormatFlags.EndEllipsis);
        string state = State == 2 ? "✓ Concluído" : State == -1 ? Number == 7 ? "× Não enviado" : "! Atenção" : State == 1 ? "◌ Em análise" : "○ Pendente";
        using var stateFont = new Font("Segoe UI", 9.5F, FontStyle.Bold);
        TextRenderer.DrawText(g, state, stateFont, new Rectangle(Width - stateWidth, cy - 23, stateWidth, 25), color, TextFormatFlags.Right | TextFormatFlags.VerticalCenter);
        if (Number < 7) g.DrawLine(line, 48, Height - 1, Width - 5, Height - 1);
    }
}
