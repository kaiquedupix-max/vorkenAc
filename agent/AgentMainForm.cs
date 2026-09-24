using System.Drawing;
using System.Windows.Forms;

namespace Vorken.Agent;

internal sealed class AgentMainForm : Form
{
    private readonly string[] _args;

    private readonly Panel _contentPanel = new();
    private readonly Label _titleLabel = new();
    private readonly Label _subtitleLabel = new();
    private readonly Label _statusTitle = new();
    private readonly Label _statusMessage = new();
    private readonly ProgressBar _progressBar = new();
    private readonly TextBox _activityBox = new();
    private readonly Button _acceptButton = new();
    private readonly Button _closeButton = new();

    private bool _running;
    private bool _finished;

    private static readonly Color Background = Color.FromArgb(8, 18, 22);
    private static readonly Color Surface = Color.FromArgb(13, 28, 33);
    private static readonly Color SurfaceAlt = Color.FromArgb(17, 37, 43);
    private static readonly Color Border = Color.FromArgb(35, 64, 70);
    private static readonly Color Accent = Color.FromArgb(72, 226, 190);
    private static readonly Color TextPrimary = Color.FromArgb(240, 247, 246);
    private static readonly Color TextSecondary = Color.FromArgb(157, 180, 181);
    private static readonly Color Warning = Color.FromArgb(246, 194, 92);
    private static readonly Color Success = Color.FromArgb(83, 220, 154);
    private static readonly Color Danger = Color.FromArgb(239, 104, 104);

    internal AgentMainForm(string[] args)
    {
        _args = args;

        Text = "Vorken Anti Cheat";
        StartPosition = FormStartPosition.CenterScreen;
        Size = new Size(820, 660);
        MinimumSize = new Size(760, 610);
        BackColor = Background;
        ForeColor = TextPrimary;
        Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;

        BuildLayout();
        ShowConsentView();

        FormClosing += OnFormClosing;
    }

    private void BuildLayout()
    {
        var header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 92,
            BackColor = Surface,
            Padding = new Padding(28, 18, 28, 12)
        };

        var logo = new Label
        {
            Text = "V",
            AutoSize = false,
            Size = new Size(44, 44),
            Location = new Point(28, 22),
            TextAlign = ContentAlignment.MiddleCenter,
            BackColor = Accent,
            ForeColor = Background,
            Font = new Font("Segoe UI", 18F, FontStyle.Bold)
        };

        _titleLabel.Text = "Vorken";
        _titleLabel.AutoSize = true;
        _titleLabel.Location = new Point(86, 21);
        _titleLabel.Font = new Font("Segoe UI", 19F, FontStyle.Bold);
        _titleLabel.ForeColor = TextPrimary;

        _subtitleLabel.Text = "ANTI CHEAT · ANÁLISE TÉCNICA";
        _subtitleLabel.AutoSize = true;
        _subtitleLabel.Location = new Point(89, 55);
        _subtitleLabel.Font = new Font("Segoe UI", 8.5F, FontStyle.Bold);
        _subtitleLabel.ForeColor = Accent;

        header.Controls.Add(logo);
        header.Controls.Add(_titleLabel);
        header.Controls.Add(_subtitleLabel);

        _contentPanel.Dock = DockStyle.Fill;
        _contentPanel.BackColor = Background;
        _contentPanel.Padding = new Padding(34, 28, 34, 28);

        Controls.Add(_contentPanel);
        Controls.Add(header);
    }

    private void ShowConsentView()
    {
        _contentPanel.Controls.Clear();

        var heading = new Label
        {
            Text = "Antes de iniciar",
            AutoSize = true,
            Location = new Point(34, 28),
            Font = new Font("Segoe UI", 20F, FontStyle.Bold),
            ForeColor = TextPrimary
        };

        var description = new Label
        {
            Text = "O Vorken coleta evidências técnicas do Windows para uma análise anti-cheat.\nA coleta só começa depois que você aceitar os termos abaixo.",
            AutoSize = true,
            MaximumSize = new Size(700, 0),
            Location = new Point(36, 73),
            Font = new Font("Segoe UI", 10.5F),
            ForeColor = TextSecondary
        };

        var termsCard = new Panel
        {
            Location = new Point(34, 132),
            Size = new Size(684, 260),
            BackColor = Surface,
            Padding = new Padding(22)
        };

        var termsTitle = new Label
        {
            Text = "O que será analisado",
            AutoSize = true,
            Location = new Point(22, 20),
            Font = new Font("Segoe UI", 12F, FontStyle.Bold),
            ForeColor = TextPrimary
        };

        var termsText = new Label
        {
            Text =
                "• USB, dispositivos seriais e hardware relacionado\n" +
                "• Prefetch, BAM, Amcache, ShimCache, PCA e USN\n" +
                "• Downloads, Zone.Identifier e vestígios do navegador\n" +
                "• Assinaturas digitais, PE/entropia e módulos carregados\n" +
                "• Autoruns, integridade do sistema, rede e outros artefatos técnicos",
            AutoSize = true,
            MaximumSize = new Size(620, 0),
            Location = new Point(24, 58),
            Font = new Font("Segoe UI", 10F),
            ForeColor = TextSecondary
        };

        var privacy = new Label
        {
            Text = "Privacidade: o Vorken não coleta senhas, cookies, mensagens, fotos ou documentos pessoais.",
            AutoSize = false,
            Size = new Size(632, 50),
            Location = new Point(24, 184),
            Padding = new Padding(12, 8, 12, 8),
            BackColor = SurfaceAlt,
            ForeColor = Warning,
            Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
        };

        termsCard.Controls.Add(termsTitle);
        termsCard.Controls.Add(termsText);
        termsCard.Controls.Add(privacy);

        _acceptButton.Text = "Aceitar os termos e iniciar análise";
        _acceptButton.Location = new Point(34, 414);
        _acceptButton.Size = new Size(330, 48);
        _acceptButton.FlatStyle = FlatStyle.Flat;
        _acceptButton.FlatAppearance.BorderSize = 0;
        _acceptButton.BackColor = Accent;
        _acceptButton.ForeColor = Background;
        _acceptButton.Font = new Font("Segoe UI", 10.5F, FontStyle.Bold);
        _acceptButton.Cursor = Cursors.Hand;
        _acceptButton.Click -= AcceptButton_Click;
        _acceptButton.Click += AcceptButton_Click;

        var cancelButton = new Button
        {
            Text = "Fechar",
            Location = new Point(378, 414),
            Size = new Size(140, 48),
            FlatStyle = FlatStyle.Flat,
            BackColor = Surface,
            ForeColor = TextSecondary,
            Font = new Font("Segoe UI", 10F, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        cancelButton.FlatAppearance.BorderColor = Border;
        cancelButton.Click += (_, _) => Close();

        var consentNote = new Label
        {
            Text = "Ao clicar em “Aceitar”, você autoriza esta coleta técnica para a análise solicitada.",
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            Location = new Point(36, 480),
            Font = new Font("Segoe UI", 8.5F),
            ForeColor = TextSecondary
        };

        _contentPanel.Controls.Add(heading);
        _contentPanel.Controls.Add(description);
        _contentPanel.Controls.Add(termsCard);
        _contentPanel.Controls.Add(_acceptButton);
        _contentPanel.Controls.Add(cancelButton);
        _contentPanel.Controls.Add(consentNote);
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
        _contentPanel.Controls.Clear();

        _statusTitle.Text = "Análise em andamento";
        _statusTitle.AutoSize = true;
        _statusTitle.Location = new Point(34, 28);
        _statusTitle.Font = new Font("Segoe UI", 20F, FontStyle.Bold);
        _statusTitle.ForeColor = TextPrimary;

        _statusMessage.Text = "Não feche esta janela enquanto a coleta estiver em andamento.";
        _statusMessage.AutoSize = true;
        _statusMessage.Location = new Point(36, 72);
        _statusMessage.Font = new Font("Segoe UI", 10F);
        _statusMessage.ForeColor = TextSecondary;

        _progressBar.Location = new Point(34, 112);
        _progressBar.Size = new Size(684, 14);
        _progressBar.Style = ProgressBarStyle.Marquee;
        _progressBar.MarqueeAnimationSpeed = 24;

        var activityTitle = new Label
        {
            Text = "Atividade",
            AutoSize = true,
            Location = new Point(34, 151),
            Font = new Font("Segoe UI", 10F, FontStyle.Bold),
            ForeColor = TextPrimary
        };

        _activityBox.Location = new Point(34, 180);
        _activityBox.Size = new Size(684, 270);
        _activityBox.Multiline = true;
        _activityBox.ReadOnly = true;
        _activityBox.ScrollBars = ScrollBars.Vertical;
        _activityBox.BackColor = Surface;
        _activityBox.ForeColor = TextSecondary;
        _activityBox.BorderStyle = BorderStyle.FixedSingle;
        _activityBox.Font = new Font("Consolas", 9F);
        _activityBox.Clear();

        var privacy = new Label
        {
            Text = "A janela permanecerá aberta quando o envio terminar.",
            AutoSize = true,
            Location = new Point(36, 472),
            Font = new Font("Segoe UI", 9F, FontStyle.Bold),
            ForeColor = Accent
        };

        _contentPanel.Controls.Add(_statusTitle);
        _contentPanel.Controls.Add(_statusMessage);
        _contentPanel.Controls.Add(_progressBar);
        _contentPanel.Controls.Add(activityTitle);
        _contentPanel.Controls.Add(_activityBox);
        _contentPanel.Controls.Add(privacy);
    }

    private void ShowCompletion(bool success)
    {
        if (InvokeRequired)
        {
            BeginInvoke((Action)(() => ShowCompletion(success)));
            return;
        }

        _progressBar.Style = ProgressBarStyle.Blocks;
        _progressBar.MarqueeAnimationSpeed = 0;
        _progressBar.Value = success ? 100 : 0;

        _statusTitle.Text = success
            ? "Dados enviados para análise"
            : "Não foi possível concluir o envio";

        _statusTitle.ForeColor = success ? Success : Danger;

        _statusMessage.Text = success
            ? "A coleta foi concluída e os dados foram enviados para o responsável analisar.\nEsta janela não será fechada automaticamente."
            : "A análise foi interrompida antes de concluir o envio. Consulte a atividade abaixo.";

        _closeButton.Text = "Fechar";
        _closeButton.Location = new Point(34, 492);
        _closeButton.Size = new Size(170, 46);
        _closeButton.FlatStyle = FlatStyle.Flat;
        _closeButton.FlatAppearance.BorderSize = 0;
        _closeButton.BackColor = success ? Accent : SurfaceAlt;
        _closeButton.ForeColor = success ? Background : TextPrimary;
        _closeButton.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
        _closeButton.Cursor = Cursors.Hand;
        _closeButton.Click -= CloseButton_Click;
        _closeButton.Click += CloseButton_Click;

        if (!_contentPanel.Controls.Contains(_closeButton))
            _contentPanel.Controls.Add(_closeButton);
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

        string line =
            $"[{DateTime.Now:HH:mm:ss}] {message.Trim()}{Environment.NewLine}";

        _activityBox.AppendText(line);
        _activityBox.SelectionStart = _activityBox.TextLength;
        _activityBox.ScrollToCaret();
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
