using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Vorken.RemoteAdmin;

internal sealed class RemoteAdminForm : Form
{
    private static readonly Color Background = Color.FromArgb(4, 10, 15);
    private static readonly Color Surface = Color.FromArgb(7, 22, 29);
    private static readonly Color Accent = Color.FromArgb(43, 239, 201);
    private static readonly Color TextPrimary = Color.FromArgb(240, 247, 248);
    private static readonly Color TextSecondary = Color.FromArgb(160, 183, 191);
    private static readonly Color Danger = Color.FromArgb(255, 72, 88);
    private static readonly Color Border = Color.FromArgb(21, 61, 76);
    private static readonly Color BorderBright = Color.FromArgb(24, 117, 141);

    private readonly AdminSurface _content = new() { Dock = DockStyle.Fill };
    private readonly Label _shellStatus = new();
    private readonly System.Windows.Forms.Timer _pollTimer = new() { Interval = 2000 };
    private HttpClient? _http;
    private string _serverUrl = "https://vorkenac.guerrafriarust.com.br";
    private string _accessToken = "";
    private List<SupportRequest> _requests = [];
    private ListBox? _requestList;
    private Label? _status;
    private PictureBox? _viewer;
    private AdminCard? _viewerPanel;
    private ComboBox? _monitorSelector;
    private Label? _administratorAccessStatus;
    private Button? _fullScreenButton;
    private Form? _fullScreenWindow;
    private bool _updatingMonitorSelector;
    private ClientWebSocket? _socket;
    private CancellationTokenSource? _sessionCancellation;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private SupportRequest? _activeRequest;
    private bool _available = true;
    private long _lastFrameSequence;
    private long _lastPointerSentAt;
    private bool _observerMode;

    public RemoteAdminForm()
    {
        Text = "Vorken · Administração Remota";
        var appIcon =
            Icon.ExtractAssociatedIcon(Application.ExecutablePath) ??
            SystemIcons.Application;
        Icon = appIcon;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1080, 720);
        Size = new Size(1320, 820);
        FormBorderStyle = FormBorderStyle.None;
        BackColor = Background;
        ForeColor = TextPrimary;
        Font = new Font("Segoe UI", 9.5F);
        KeyPreview = true;
        BuildShell();
        _pollTimer.Tick += async (_, _) => await RefreshRequestsAsync();
        FormClosing += async (_, _) => await EndViewerAsync(false);
        KeyDown += async (_, e) => await SendKeyAsync(e.KeyValue, false);
        KeyUp += async (_, e) => await SendKeyAsync(e.KeyValue, true);
        ShowLogin();
    }

    private void BuildShell()
    {
        var frame = new AdminFrame { Dock = DockStyle.Fill, BackColor = Background, BorderColor = BorderBright };
        var header = new Panel { Dock = DockStyle.Top, Height = 88, BackColor = Color.FromArgb(5, 15, 22) };
        header.MouseDown += HeaderMouseDown;

        var mark = new PictureBox
        {
            BackColor = Accent,
            Image = (Icon ?? SystemIcons.Application).ToBitmap(),
            SizeMode = PictureBoxSizeMode.Zoom,
            Padding = new Padding(8)
        };
        mark.SetBounds(32, 18, 52, 52);
        ApplyRounded(mark, 8);
        header.Controls.Add(mark);
        header.Controls.Add(LabelAt("VORKEN", 101, 17, 190, 28, 17F, TextPrimary, FontStyle.Bold));
        header.Controls.Add(LabelAt("REMOTE ADMIN", 103, 49, 180, 20, 8.5F, Accent, FontStyle.Bold));

        var section = LabelAt("◉   CENTRAL DE SUPORTE", 330, 27, 310, 36, 9F, TextSecondary, FontStyle.Bold);
        section.TextAlign = ContentAlignment.MiddleCenter;
        section.BackColor = Color.FromArgb(6, 25, 32);
        ApplyRounded(section, 10);
        header.Controls.Add(section);

        _shellStatus.Text = "●  OFFLINE";
        _shellStatus.TextAlign = ContentAlignment.MiddleCenter;
        _shellStatus.Font = new Font("Consolas", 8.5F, FontStyle.Bold);
        _shellStatus.ForeColor = TextSecondary;
        _shellStatus.BackColor = Color.FromArgb(6, 31, 36);
        _shellStatus.SetBounds(1010, 27, 150, 36);
        ApplyRounded(_shellStatus, 9);
        header.Controls.Add(_shellStatus);

        var minimize = WindowButton("—");
        var maximize = WindowButton("□");
        var close = WindowButton("×");
        minimize.Click += (_, _) => WindowState = FormWindowState.Minimized;
        maximize.Click += (_, _) => WindowState = WindowState == FormWindowState.Maximized ? FormWindowState.Normal : FormWindowState.Maximized;
        close.Click += (_, _) => Close();
        header.Controls.Add(minimize); header.Controls.Add(maximize); header.Controls.Add(close);
        header.Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = Border });

        frame.Controls.Add(_content);
        frame.Controls.Add(header);
        Controls.Add(frame);
        Resize += (_, _) =>
        {
            _shellStatus.Left = Math.Max(760, ClientSize.Width - 300);
            minimize.Left = ClientSize.Width - 118;
            maximize.Left = ClientSize.Width - 80;
            close.Left = ClientSize.Width - 42;
        };
        minimize.SetBounds(ClientSize.Width - 118, 2, 38, 36);
        maximize.SetBounds(ClientSize.Width - 80, 2, 38, 36);
        close.SetBounds(ClientSize.Width - 42, 2, 38, 36);
    }

    private static Button WindowButton(string text)
    {
        var button = new Button { Text = text, FlatStyle = FlatStyle.Flat, BackColor = Color.Transparent, ForeColor = TextSecondary, Font = new Font("Segoe UI", 10F), Cursor = Cursors.Hand, TabStop = false };
        button.FlatAppearance.BorderSize = 0;
        button.FlatAppearance.MouseOverBackColor = text == "×" ? Color.FromArgb(80, 180, 45, 55) : Color.FromArgb(20, 45, 55);
        return button;
    }

    private void ShowLogin()
    {
        SavedCredentials? saved = CredentialStore.Load();
        _content.Controls.Clear();
        _shellStatus.Text = "●  LOGIN";
        _shellStatus.ForeColor = TextSecondary;
        var badge = Badge("ACESSO RESTRITO   ·   ADMINISTRAÇÃO VORKEN");
        badge.Location = new Point(54, 34);
        _content.Controls.Add(badge);
        _content.Controls.Add(LabelAt("Central de suporte remoto", 54, 77, 720, 52, 29F, TextPrimary, FontStyle.Bold));
        _content.Controls.Add(LabelAt("Entre com sua conta administrativa para ficar disponível aos jogadores.", 57, 130, 760, 28, 10.2F, TextSecondary));

        var card = new AdminCard { Bounds = new Rectangle(54, 185, 610, 470), BackColor = Surface };
        card.Controls.Add(LabelAt("IDENTIFICAÇÃO DO ADMINISTRADOR", 28, 24, 500, 30, 12F, TextPrimary, FontStyle.Bold));
        card.Controls.Add(LabelAt("Use suas credenciais individuais. A disponibilidade só é ativada após o login.", 28, 57, 530, 38, 8.8F, TextSecondary));
        if (!string.IsNullOrWhiteSpace(saved?.ServerUrl)) _serverUrl = saved.ServerUrl;
        var server = Input(_serverUrl, 28, 126, false, 550);
        var user = Input(saved?.Username ?? "", 28, 207, false, 550);
        var password = Input(saved?.Password ?? "", 28, 288, true, 550);
        card.Controls.Add(LabelAt("SERVIDOR VORKEN", 28, 104, 240, 20, 8F, TextSecondary, FontStyle.Bold));
        card.Controls.Add(LabelAt("USUÁRIO", 28, 185, 240, 20, 8F, TextSecondary, FontStyle.Bold));
        card.Controls.Add(LabelAt("SENHA", 28, 266, 240, 20, 8F, TextSecondary, FontStyle.Bold));
        card.Controls.Add(server); card.Controls.Add(user); card.Controls.Add(password);
        var remember = new CheckBox { Text = "Salvar usuário e senha neste computador", Checked = saved is not null, Bounds = new Rectangle(28, 337, 340, 25), ForeColor = TextSecondary, BackColor = Color.Transparent, Font = new Font("Segoe UI", 8.5F), Cursor = Cursors.Hand };
        var login = Button("ENTRAR NO PAINEL   →", 28, 378, 245, 50, Accent);
        var message = LabelAt("", 292, 386, 285, 42, 8.7F, Danger, FontStyle.Bold);
        card.Controls.Add(remember); card.Controls.Add(login); card.Controls.Add(message);
        _content.Controls.Add(card);

        var info = new AdminCard { Bounds = new Rectangle(692, 185, 535, 470), BackColor = Color.FromArgb(5, 18, 24) };
        info.Controls.Add(LabelAt("SESSÕES SOB CONTROLE", 28, 26, 430, 30, 12F, Accent, FontStyle.Bold));
        info.Controls.Add(LabelAt("Solicitações direcionadas exigem aceite. Sessões ao vivo podem ser acompanhadas por outros administradores somente para visualização.", 28, 66, 465, 60, 10F, TextSecondary));
        info.Controls.Add(SecurityRow("01", "Consentimento duplo", "O jogador solicita e o administrador aceita.", 28, 148));
        info.Controls.Add(SecurityRow("02", "Permissão limitada", "Visualização ou controle, conforme escolhido.", 28, 226));
        info.Controls.Add(SecurityRow("03", "Encerramento imediato", "Qualquer lado pode finalizar a sessão.", 28, 304));
        info.Controls.Add(LabelAt("●  CONEXÕES CRIPTOGRAFADAS VIA WSS", 28, 409, 450, 24, 8.2F, Accent, FontStyle.Bold));
        _content.Controls.Add(info);

        login.Click += async (_, _) =>
        {
            login.Enabled = false;
            try
            {
                _serverUrl = server.Text.Trim().TrimEnd('/');
                _http?.Dispose();
                _http = new HttpClient { BaseAddress = new Uri(_serverUrl + "/"), Timeout = TimeSpan.FromSeconds(20) };
                var response = await _http.PostAsJsonAsync("api/remote/admin/login", new { username = user.Text.Trim(), password = password.Text });
                if (!response.IsSuccessStatusCode) throw new InvalidOperationException("Usuário ou senha inválidos.");
                var result = await response.Content.ReadFromJsonAsync<LoginResponse>() ?? throw new InvalidOperationException("Resposta inválida.");
                _accessToken = result.AccessToken;
                _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
                if (remember.Checked)
                    CredentialStore.Save(new SavedCredentials(_serverUrl, user.Text.Trim(), password.Text));
                else
                    CredentialStore.Delete();
                _shellStatus.Text = "●  ONLINE";
                _shellStatus.ForeColor = Accent;
                ShowDashboard(result.DisplayName);
            }
            catch (Exception ex) { message.Text = ex.Message; }
            finally { if (!login.IsDisposed) login.Enabled = true; }
        };
    }

    private void ShowDashboard(string displayName)
    {
        _content.Controls.Clear();
        var badge = Badge("ADMINISTRADOR ONLINE   ·   SUPORTE REMOTO");
        badge.Location = new Point(38, 24);
        _content.Controls.Add(badge);
        _content.Controls.Add(LabelAt("Solicitações e sessão ao vivo", 38, 64, 650, 48, 25F, TextPrimary, FontStyle.Bold));
        _content.Controls.Add(LabelAt("Conectado como " + displayName, 41, 110, 500, 24, 9.2F, TextSecondary));

        var presence = new AdminCard { Bounds = new Rectangle(1000, 29, 245, 92), BackColor = Color.FromArgb(5, 18, 24) };
        presence.Controls.Add(LabelAt("STATUS DE ATENDIMENTO", 18, 13, 210, 20, 7.4F, TextSecondary, FontStyle.Bold));
        var available = new CheckBox { Text = "Disponível", Checked = true, Bounds = new Rectangle(18, 40, 190, 34), ForeColor = Accent, BackColor = Color.Transparent, Font = new Font("Segoe UI", 10F, FontStyle.Bold), Cursor = Cursors.Hand };
        presence.Controls.Add(available);
        _content.Controls.Add(presence);

        var left = new AdminCard { Bounds = new Rectangle(38, 155, 350, 530), BackColor = Color.FromArgb(5, 18, 24) };
        left.Controls.Add(LabelAt("SOLICITAÇÕES", 22, 18, 280, 30, 11F, TextPrimary, FontStyle.Bold));
        left.Controls.Add(LabelAt("Selecione uma conexão pendente", 22, 47, 280, 22, 8.4F, TextSecondary));
        _requestList = new ListBox { Bounds = new Rectangle(22, 82, 306, 310), BackColor = Color.FromArgb(3, 13, 18), ForeColor = TextPrimary, BorderStyle = BorderStyle.None, Font = new Font("Segoe UI", 9.5F), ItemHeight = 52, DrawMode = DrawMode.OwnerDrawFixed };
        _requestList.DrawItem += DrawRequestItem;
        left.Controls.Add(_requestList);
        var accept = Button("ACEITAR", 22, 410, 146, 44, Accent);
        var reject = Button("RECUSAR", 182, 410, 146, 44, Danger);
        left.Controls.Add(accept); left.Controls.Add(reject);
        _status = LabelAt("Aguardando solicitações...", 22, 472, 306, 42, 8.6F, TextSecondary, FontStyle.Bold);
        left.Controls.Add(_status);
        _content.Controls.Add(left);

        var viewerPanel = new AdminCard { Bounds = new Rectangle(410, 155, 835, 530), BackColor = Color.FromArgb(3, 12, 17) };
        _viewerPanel = viewerPanel;
        viewerPanel.Controls.Add(LabelAt("SESSÃO AO VIVO", 22, 17, 260, 28, 10.5F, TextPrimary, FontStyle.Bold));
        viewerPanel.Controls.Add(LabelAt("A tela aparecerá após o aceite dos dois lados", 22, 44, 420, 22, 8.2F, TextSecondary));
        _administratorAccessStatus = LabelAt("ADMIN: verificando...", 350, 28, 155, 25, 7.4F, TextSecondary, FontStyle.Bold);
        _administratorAccessStatus.TextAlign = ContentAlignment.MiddleCenter;
        viewerPanel.Controls.Add(_administratorAccessStatus);
        _monitorSelector = new ComboBox
        {
            Bounds = new Rectangle(510, 24, 150, 34),
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = Color.FromArgb(5, 25, 32),
            ForeColor = TextPrimary,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            Enabled = false
        };
        viewerPanel.Controls.Add(_monitorSelector);
        _fullScreenButton = Button("⛶  TELA CHEIA", 665, 22, 145, 40, Color.FromArgb(12, 67, 72));
        viewerPanel.Controls.Add(_fullScreenButton);
        _viewer = new PictureBox { Bounds = new Rectangle(18, 82, 799, 430), BackColor = Color.Black, SizeMode = PictureBoxSizeMode.Zoom, TabStop = true };
        _viewer.Paint += (_, e) =>
        {
            if (_viewer.Image is not null) return;
            using var font = new Font("Segoe UI", 10F, FontStyle.Bold);
            TextRenderer.DrawText(e.Graphics, "◉\n\nAGUARDANDO UMA SESSÃO", font, _viewer.ClientRectangle, TextSecondary,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        };
        viewerPanel.Controls.Add(_viewer);
        var end = Button("■  ENCERRAR", 815, 22, 145, 40, Danger);
        end.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        end.BringToFront();
        viewerPanel.Controls.Add(end);
        _content.Controls.Add(viewerPanel);

        void LayoutViewerPanel()
        {
            _viewer.Width = viewerPanel.ClientSize.Width - 36;
            _viewer.Height = viewerPanel.ClientSize.Height - 100;
            end.Left = viewerPanel.ClientSize.Width - end.Width - 20;
            _fullScreenButton.Left = end.Left - _fullScreenButton.Width - 10;
            _monitorSelector.Left = _fullScreenButton.Left - _monitorSelector.Width - 10;
            _administratorAccessStatus.Left = _monitorSelector.Left - _administratorAccessStatus.Width - 10;
            _administratorAccessStatus.Visible = viewerPanel.ClientSize.Width >= 760;
        }

        void LayoutDashboard()
        {
            presence.Left = Math.Max(760, _content.ClientSize.Width - presence.Width - 38);
            left.Height = Math.Max(490, _content.ClientSize.Height - 170);
            viewerPanel.Left = left.Right + 22;
            viewerPanel.Width = Math.Max(520, _content.ClientSize.Width - viewerPanel.Left - 38);
            viewerPanel.Height = left.Height;
            LayoutViewerPanel();
        }
        _content.Resize += (_, _) => LayoutDashboard();
        viewerPanel.Resize += (_, _) => LayoutViewerPanel();
        LayoutDashboard();

        available.CheckedChanged += async (_, _) =>
        {
            _available = available.Checked;
            await SetPresenceAsync(_available);
        };
        accept.Click += async (_, _) => await DecideSelectedAsync("accept");
        reject.Click += async (_, _) => await DecideSelectedAsync("reject");
        _requestList.SelectedIndexChanged += (_, _) =>
        {
            if (_requestList.SelectedItem is not RequestListItem selected) return;
            bool live = selected.Request.Status == "accepted";
            accept.Text = live ? "ASSISTIR AO VIVO" : "ACEITAR";
            reject.Enabled = !live || !selected.Request.CanObserve;
        };
        end.Click += async (_, _) => await EndViewerAsync(true);
        _fullScreenButton.Click += (_, _) => ToggleFullScreenViewer();
        _monitorSelector.SelectedIndexChanged += async (_, _) =>
        {
            if (_updatingMonitorSelector || _monitorSelector.SelectedItem is not MonitorOption option)
                return;
            await SelectMonitorAsync(option.Index);
        };
        _viewer.MouseMove += async (_, e) => await SendPointerAsync(e, "move");
        _viewer.MouseDown += async (_, e) => await SendPointerAsync(e, e.Button == MouseButtons.Left ? "leftDown" : "rightDown");
        _viewer.MouseUp += async (_, e) => await SendPointerAsync(e, e.Button == MouseButtons.Left ? "leftUp" : "rightUp");

        _pollTimer.Start();
        _ = SetPresenceAsync(true);
        _ = RefreshRequestsAsync();
    }

    private async Task SetPresenceAsync(bool available)
    {
        if (_http is null) return;
        try { await _http.PostAsJsonAsync("api/remote/admin/presence", new { available }); } catch { }
    }

    private async Task RefreshRequestsAsync()
    {
        if (_http is null || _requestList is null) return;
        try
        {
            await SetPresenceAsync(_available);
            var response = await _http.GetFromJsonAsync<RequestsResponse>("api/remote/admin/requests");
            _requests = response?.Requests ?? [];
            string? selectedId = (_requestList.SelectedItem as RequestListItem)?.Request.Id;
            _requestList.Items.Clear();
            foreach (var request in _requests)
            {
                var item = new RequestListItem(request);
                int index = _requestList.Items.Add(item);
                if (request.Id == selectedId) _requestList.SelectedIndex = index;
            }
            if (_status is not null && _activeRequest is null)
                _status.Text = _requests.Count == 0 ? "Disponível · nenhuma solicitação pendente." : $"{_requests.Count} solicitação(ões) aguardando.";
            if (_activeRequest is not null)
                await RefreshMonitorsAsync();
        }
        catch (Exception ex) { if (_status is not null) _status.Text = "Falha de conexão: " + ex.Message; }
    }

    private async Task DecideSelectedAsync(string decision)
    {
        if (_http is null || _requestList?.SelectedItem is not RequestListItem item) return;
        try
        {
            if (decision == "accept" && item.Request.Status == "accepted")
            {
                if (item.Request.CanObserve)
                {
                    var watch = await _http.PostAsync($"api/remote/admin/sessions/{item.Request.Id}/watch", null);
                    watch.EnsureSuccessStatusCode();
                }
                await OpenViewerAsync(item.Request, item.Request.CanObserve);
                return;
            }
            var response = await _http.PostAsync($"api/remote/admin/sessions/{item.Request.Id}/{decision}", null);
            if (!response.IsSuccessStatusCode) return;
            if (decision == "accept") await OpenViewerAsync(item.Request, false);
            await RefreshRequestsAsync();
        }
        catch (Exception ex)
        {
            if (_status is not null) _status.Text = "Não foi possível abrir a sessão: " + ex.Message;
            await EndViewerAsync(false);
        }
    }

    private async Task OpenViewerAsync(SupportRequest request, bool observerMode)
    {
        await EndViewerAsync(false);
        _activeRequest = request;
        _observerMode = observerMode;
        _sessionCancellation = new CancellationTokenSource();
        _lastFrameSequence = 0;
        if (observerMode)
        {
            if (_status is not null) _status.Text = "Assistindo sessão ao vivo · SOMENTE TELA";
            _ = PollFramesHttpAsync(_sessionCancellation.Token);
            _viewer?.Focus();
            return;
        }
        try
        {
            _socket = new ClientWebSocket();
            var wsUrl = new Uri(_serverUrl.Replace("https://", "wss://").Replace("http://", "ws://") + "/ws/remote");
            await _socket.ConnectAsync(wsUrl, _sessionCancellation.Token);
            await SendJsonAsync(new { type = "authenticate", role = "admin", sessionId = request.Id, accessToken = _accessToken });
            if (_status is not null) _status.Text = request.Mode == "control" ? "Sessão ativa · TELA + CONTROLE" : "Sessão ativa · SOMENTE VISUALIZAÇÃO";
            _ = ReceiveFramesAsync(_sessionCancellation.Token);
        }
        catch (Exception ex) when (
            (ex is WebSocketException or HttpRequestException or InvalidOperationException) &&
            !_sessionCancellation.IsCancellationRequested)
        {
            _socket?.Dispose();
            _socket = null;
            if (_status is not null)
                _status.Text = request.Mode == "control"
                    ? "Sessão ativa · TELA + CONTROLE · HTTPS COMPATÍVEL"
                    : "Sessão ativa · SOMENTE TELA · HTTPS COMPATÍVEL";
            _ = PollFramesHttpAsync(_sessionCancellation.Token);
        }
        await RefreshMonitorsAsync();
        _viewer?.Focus();
    }

    private async Task RefreshMonitorsAsync()
    {
        if (_http is null || _activeRequest is null || _monitorSelector is null)
            return;

        try
        {
            string id = Uri.EscapeDataString(_activeRequest.Id);
            var state = await _http.GetFromJsonAsync<MonitorState>(
                $"api/remote/admin/sessions/{id}/monitors");
            if (state is null)
                return;

            _updatingMonitorSelector = true;
            int previous = (_monitorSelector.SelectedItem as MonitorOption)?.Index ?? -1;
            _monitorSelector.Items.Clear();
            foreach (MonitorInfo monitor in state.Monitors)
                _monitorSelector.Items.Add(new MonitorOption(monitor));

            int wanted = previous >= 0 ? previous : state.SelectedIndex;
            int selected = state.Monitors.FindIndex(item => item.Index == wanted);
            if (_monitorSelector.Items.Count > 0)
                _monitorSelector.SelectedIndex = selected >= 0 ? selected : 0;
            _monitorSelector.Enabled = !_observerMode && _monitorSelector.Items.Count > 1;
            _updatingMonitorSelector = false;

            if (_administratorAccessStatus is not null)
            {
                _administratorAccessStatus.Text = state.Elevated
                    ? "● ADMIN ATIVO"
                    : "○ SEM ELEVAÇÃO";
                _administratorAccessStatus.ForeColor = state.Elevated ? Accent : Danger;
            }
        }
        catch
        {
            _updatingMonitorSelector = false;
        }
    }

    private async Task SelectMonitorAsync(int index)
    {
        if (_http is null || _activeRequest is null || _observerMode)
            return;
        string id = Uri.EscapeDataString(_activeRequest.Id);
        using var response = await _http.PostAsJsonAsync(
            $"api/remote/admin/sessions/{id}/input",
            new { type = "monitor", index });
        if (!response.IsSuccessStatusCode && _status is not null)
            _status.Text = "Não foi possível trocar o monitor remoto.";
    }

    private void ToggleFullScreenViewer()
    {
        if (_viewerPanel is null || _viewer is null)
            return;

        if (_fullScreenWindow is not null)
        {
            _fullScreenWindow.Close();
            return;
        }

        Control? originalParent = _viewerPanel.Parent;
        Rectangle originalBounds = _viewerPanel.Bounds;
        DockStyle originalDock = _viewerPanel.Dock;
        var window = new Form
        {
            Text = "Vorken · Sessão remota",
            Icon = Icon,
            BackColor = Color.Black,
            FormBorderStyle = FormBorderStyle.None,
            WindowState = FormWindowState.Maximized,
            KeyPreview = true,
            StartPosition = FormStartPosition.Manual,
            Bounds = Screen.FromControl(this).Bounds
        };
        _fullScreenWindow = window;
        _viewerPanel.Parent = window;
        _viewerPanel.Dock = DockStyle.Fill;
        _fullScreenButton!.Text = "⤢  SAIR DA TELA CHEIA";

        void Restore()
        {
            if (_viewerPanel is null || originalParent is null)
                return;
            _viewerPanel.Parent = originalParent;
            _viewerPanel.Dock = originalDock;
            _viewerPanel.Bounds = originalBounds;
            _fullScreenWindow = null;
            if (_fullScreenButton is not null)
                _fullScreenButton.Text = "⛶  TELA CHEIA";
        }

        window.FormClosed += (_, _) => Restore();
        window.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Escape || e.KeyCode == Keys.F11)
            {
                window.Close();
                e.Handled = true;
            }
            else
            {
                _ = SendKeyAsync(e.KeyValue, false);
            }
        };
        window.KeyUp += (_, e) =>
        {
            if (e.KeyCode != Keys.Escape && e.KeyCode != Keys.F11)
                _ = SendKeyAsync(e.KeyValue, true);
        };
        window.Show(this);
        _viewer.Focus();
    }

    private async Task ReceiveFramesAsync(CancellationToken cancellationToken)
    {
        try
        {
            byte[] buffer = new byte[2 * 1024 * 1024];
            while (_socket?.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
            {
                using var frame = new MemoryStream();
                WebSocketReceiveResult result;
                do
                {
                    result = await _socket.ReceiveAsync(buffer, cancellationToken);
                    if (result.MessageType == WebSocketMessageType.Close) return;
                    if (result.MessageType == WebSocketMessageType.Binary) frame.Write(buffer, 0, result.Count);
                } while (!result.EndOfMessage);
                if (result.MessageType != WebSocketMessageType.Binary || frame.Length == 0) continue;
                ShowFrame(frame.ToArray());
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            _socket?.Dispose();
            _socket = null;
            if (_status is not null) _status.Text = "Reconectando pelo modo HTTPS compatível...";
            await PollFramesHttpAsync(cancellationToken);
        }
    }

    private async Task PollFramesHttpAsync(CancellationToken cancellationToken)
    {
        if (_http is null) return;
        try
        {
            while (_activeRequest is not null && !cancellationToken.IsCancellationRequested)
            {
                string id = Uri.EscapeDataString(_activeRequest.Id);
                using HttpResponseMessage response = await _http.GetAsync(
                    $"api/remote/admin/sessions/{id}/frame?after={_lastFrameSequence}", cancellationToken);
                if (response.StatusCode == System.Net.HttpStatusCode.NoContent)
                {
                    await Task.Delay(120, cancellationToken);
                    continue;
                }
                response.EnsureSuccessStatusCode();
                if (response.Headers.TryGetValues("X-Frame-Sequence", out var values) &&
                    long.TryParse(values.FirstOrDefault(), out long sequence))
                    _lastFrameSequence = Math.Max(_lastFrameSequence, sequence);
                byte[] frame = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                if (frame.Length > 0) ShowFrame(frame);
                await Task.Delay(75, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (_status is not null && !cancellationToken.IsCancellationRequested)
                _status.Text = "Conexão interrompida: " + ex.Message;
        }
    }

    private void ShowFrame(byte[] frame)
    {
        using var stream = new MemoryStream(frame);
        using var source = Image.FromStream(stream);
        var image = new Bitmap(source);
        if (IsDisposed) { image.Dispose(); return; }
        BeginInvoke(() =>
        {
            if (_viewer is null) { image.Dispose(); return; }
            Image? old = _viewer.Image;
            _viewer.Image = image;
            old?.Dispose();
        });
    }

    private async Task SendPointerAsync(MouseEventArgs e, string action)
    {
        if (_observerMode || _activeRequest?.Mode != "control" || _viewer?.Image is null || _viewer.Width <= 0 || _viewer.Height <= 0) return;
        long now = Environment.TickCount64;
        if (action == "move" && now - _lastPointerSentAt < 50) return;
        _lastPointerSentAt = now;
        double scale = Math.Min(_viewer.Width / (double)_viewer.Image.Width, _viewer.Height / (double)_viewer.Image.Height);
        double shownWidth = _viewer.Image.Width * scale;
        double shownHeight = _viewer.Image.Height * scale;
        double offsetX = (_viewer.Width - shownWidth) / 2d;
        double offsetY = (_viewer.Height - shownHeight) / 2d;
        if (e.X < offsetX || e.X > offsetX + shownWidth || e.Y < offsetY || e.Y > offsetY + shownHeight) return;
        await SendJsonAsync(new
        {
            type = "pointer",
            x = Math.Clamp((e.X - offsetX) / shownWidth, 0, 1),
            y = Math.Clamp((e.Y - offsetY) / shownHeight, 0, 1),
            action
        });
    }

    private async Task SendKeyAsync(int keyCode, bool up)
    {
        if (_observerMode || _activeRequest?.Mode != "control") return;
        await SendJsonAsync(new { type = "key", keyCode, up });
    }

    private async Task SendJsonAsync(object value)
    {
        await _sendLock.WaitAsync();
        try
        {
            if (_socket?.State == WebSocketState.Open)
            {
                await _socket.SendAsync(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)), WebSocketMessageType.Text, true, CancellationToken.None);
            }
            else if (_http is not null && !_observerMode && _activeRequest?.Mode == "control")
            {
                string id = Uri.EscapeDataString(_activeRequest.Id);
                using var response = await _http.PostAsJsonAsync($"api/remote/admin/sessions/{id}/input", value);
            }
        }
        catch { }
        finally { _sendLock.Release(); }
    }

    private async Task EndViewerAsync(bool notifyServer)
    {
        SupportRequest? active = _activeRequest;
        bool wasObserver = _observerMode;
        _activeRequest = null;
        _observerMode = false;
        _sessionCancellation?.Cancel();
        if (_socket is { State: WebSocketState.Open })
        {
            try { await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Encerrada", CancellationToken.None); } catch { }
        }
        _socket?.Dispose(); _socket = null;
        _lastFrameSequence = 0;
        _sessionCancellation?.Dispose(); _sessionCancellation = null;
        if (notifyServer && !wasObserver && active is not null && _http is not null)
            try { await _http.PostAsync($"api/remote/admin/sessions/{active.Id}/end", null); } catch { }
        if (_viewer is not null) { Image? old = _viewer.Image; _viewer.Image = null; old?.Dispose(); }
        if (_status is not null) _status.Text = "Sessão encerrada.";
        if (_fullScreenWindow is not null)
            _fullScreenWindow.Close();
        if (_monitorSelector is not null)
        {
            _monitorSelector.Items.Clear();
            _monitorSelector.Enabled = false;
        }
        if (_administratorAccessStatus is not null)
        {
            _administratorAccessStatus.Text = "ADMIN: aguardando";
            _administratorAccessStatus.ForeColor = TextSecondary;
        }
    }

    private void DrawRequestItem(object? sender, DrawItemEventArgs e)
    {
        if (_requestList is null || e.Index < 0 || e.Index >= _requestList.Items.Count) return;
        bool selected = (e.State & DrawItemState.Selected) != 0;
        e.Graphics.FillRectangle(new SolidBrush(selected ? Color.FromArgb(8, 52, 58) : Color.FromArgb(3, 13, 18)), e.Bounds);
        if (_requestList.Items[e.Index] is RequestListItem item)
        {
            Color modeColor = item.Request.Mode == "control" ? Color.FromArgb(255, 190, 55) : Accent;
            TextRenderer.DrawText(e.Graphics, item.Request.Label, new Font("Segoe UI", 9.4F, FontStyle.Bold),
                new Rectangle(e.Bounds.X + 12, e.Bounds.Y + 7, e.Bounds.Width - 24, 20), TextPrimary, TextFormatFlags.EndEllipsis);
            TextRenderer.DrawText(e.Graphics,
                item.Request.Status == "accepted"
                    ? $"● AO VIVO · {(item.Request.CanObserve ? "ASSISTIR" : item.Request.Mode == "control" ? "TELA + CONTROLE" : "SOMENTE TELA")}"
                    : item.Request.Mode == "control" ? "TELA + CONTROLE" : "SOMENTE TELA",
                new Font("Consolas", 7.5F, FontStyle.Bold),
                new Rectangle(e.Bounds.X + 12, e.Bounds.Y + 29, e.Bounds.Width - 24, 18), modeColor);
        }
        e.DrawFocusRectangle();
    }

    private static Panel SecurityRow(string number, string title, string description, int x, int y)
    {
        var row = new Panel { Bounds = new Rectangle(x, y, 470, 64), BackColor = Color.Transparent };
        var index = LabelAt(number, 0, 4, 46, 46, 10F, Accent, FontStyle.Bold);
        index.TextAlign = ContentAlignment.MiddleCenter;
        index.BackColor = Color.FromArgb(6, 35, 40);
        ApplyRounded(index, 10);
        row.Controls.Add(index);
        row.Controls.Add(LabelAt(title, 62, 2, 380, 24, 10F, TextPrimary, FontStyle.Bold));
        row.Controls.Add(LabelAt(description, 62, 28, 390, 30, 8.5F, TextSecondary));
        return row;
    }

    private static Label Badge(string text)
    {
        var label = Label(text, 7.8F, Accent, FontStyle.Bold);
        label.AutoSize = false;
        label.Size = new Size(340, 30);
        label.TextAlign = ContentAlignment.MiddleCenter;
        label.BackColor = Color.FromArgb(6, 35, 40);
        ApplyRounded(label, 8);
        return label;
    }

    private static TextBox Input(string text, int x, int y, bool password, int width = 460) => new()
    {
        Text = text,
        Bounds = new Rectangle(x, y, width, 42),
        BackColor = Color.FromArgb(3, 14, 19),
        ForeColor = TextPrimary,
        BorderStyle = BorderStyle.FixedSingle,
        UseSystemPasswordChar = password,
        Font = new Font("Segoe UI", 10.5F)
    };

    private static Button Button(string text, int x, int y, int w, int h, Color color)
    {
        var b = new Button { Text = text, Bounds = new Rectangle(x, y, w, h), BackColor = color, ForeColor = color == Accent ? Color.FromArgb(2, 20, 20) : Color.White, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9F, FontStyle.Bold), Cursor = Cursors.Hand };
        b.FlatAppearance.BorderSize = color == Accent ? 1 : 0;
        b.FlatAppearance.BorderColor = color == Accent ? Color.FromArgb(98, 255, 224) : color;
        b.FlatAppearance.MouseDownBackColor = color == Accent ? Color.FromArgb(29, 205, 174) : Color.FromArgb(190, 45, 58);
        ApplyRounded(b, 12);
        Color normal = b.BackColor;
        b.MouseEnter += (_, _) => b.BackColor = color == Accent ? Color.FromArgb(81, 250, 215) : Color.FromArgb(235, 66, 82);
        b.MouseLeave += (_, _) => b.BackColor = normal;
        return b;
    }

    private static void ApplyRounded(Control control, int radius)
    {
        void Update()
        {
            if (control.Width <= 1 || control.Height <= 1) return;
            using GraphicsPath path = AdminGeometry.Rounded(new Rectangle(0, 0, control.Width, control.Height), radius);
            Region? old = control.Region;
            control.Region = new Region(path);
            old?.Dispose();
        }
        control.Resize += (_, _) => Update();
        Update();
    }

    private void HeaderMouseDown(object? sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left || WindowState == FormWindowState.Maximized) return;
        ReleaseCapture();
        SendMessage(Handle, 0xA1, 0x2, 0);
    }

    [DllImport("user32.dll")] private static extern bool ReleaseCapture();
    [DllImport("user32.dll")] private static extern IntPtr SendMessage(IntPtr handle, int message, int wParam, int lParam);

    private static Label Label(string text, float size, Color color, FontStyle style = FontStyle.Regular) => new() { Text = text, ForeColor = color, BackColor = Color.Transparent, Font = new Font("Segoe UI", size, style) };
    private static Label LabelAt(string text, int x, int y, int w, int h, float size, Color color, FontStyle style = FontStyle.Regular) { var label = Label(text, size, color, style); label.SetBounds(x, y, w, h); return label; }

    private sealed class LoginResponse { public string AccessToken { get; set; } = ""; public string DisplayName { get; set; } = ""; }
    private sealed class RequestsResponse { public List<SupportRequest> Requests { get; set; } = []; }
    private sealed class MonitorState { public List<MonitorInfo> Monitors { get; set; } = []; public int SelectedIndex { get; set; } public bool Elevated { get; set; } }
    private sealed class MonitorInfo { public int Index { get; set; } public string Name { get; set; } = ""; public int Width { get; set; } public int Height { get; set; } public bool Primary { get; set; } }
    private sealed record MonitorOption(MonitorInfo Monitor)
    {
        public int Index => Monitor.Index;
        public override string ToString() => $"Monitor {Monitor.Index + 1} · {Monitor.Width}×{Monitor.Height}{(Monitor.Primary ? " · Principal" : "")}";
    }
    private sealed class SupportRequest { public string Id { get; set; } = ""; public string Mode { get; set; } = "view"; public string Status { get; set; } = ""; public string Label { get; set; } = ""; public string? MachineName { get; set; } public bool CanObserve { get; set; } public string OwnerDisplayName { get; set; } = ""; }
    private sealed record RequestListItem(SupportRequest Request) { public override string ToString() => $"{Request.Label}  ·  {(Request.Mode == "control" ? "CONTROLE" : "TELA")}"; }
}

internal sealed record SavedCredentials(string ServerUrl, string Username, string Password);

internal static class CredentialStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Vorken.RemoteAdmin.Credentials.v1");
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Vorken", "RemoteAdmin", "credentials.bin");

    internal static SavedCredentials? Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return null;
            byte[] encrypted = File.ReadAllBytes(FilePath);
            byte[] clear = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
            return JsonSerializer.Deserialize<SavedCredentials>(clear);
        }
        catch { return null; }
    }

    internal static void Save(SavedCredentials credentials)
    {
        byte[] clear = JsonSerializer.SerializeToUtf8Bytes(credentials);
        byte[] encrypted = ProtectedData.Protect(clear, Entropy, DataProtectionScope.CurrentUser);
        string? directory = Path.GetDirectoryName(FilePath);
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        File.WriteAllBytes(FilePath, encrypted);
        CryptographicOperations.ZeroMemory(clear);
    }

    internal static void Delete()
    {
        try { if (File.Exists(FilePath)) File.Delete(FilePath); } catch { }
    }
}

internal static class AdminGeometry
{
    internal static GraphicsPath Rounded(Rectangle bounds, int radius)
    {
        var path = new GraphicsPath();
        int safe = Math.Max(1, Math.Min(radius, Math.Min(bounds.Width, bounds.Height) / 2));
        int diameter = safe * 2;
        var arc = new Rectangle(bounds.X, bounds.Y, diameter, diameter);
        path.AddArc(arc, 180, 90);
        arc.X = bounds.Right - diameter - 1; path.AddArc(arc, 270, 90);
        arc.Y = bounds.Bottom - diameter - 1; path.AddArc(arc, 0, 90);
        arc.X = bounds.X; path.AddArc(arc, 90, 90);
        path.CloseFigure();
        return path;
    }
}

internal class AdminFrame : Panel
{
    internal Color BorderColor { get; set; } = Color.FromArgb(24, 117, 141);
    internal int CornerRadius { get; set; } = 18;
    internal AdminFrame() { DoubleBuffered = true; ResizeRedraw = true; Padding = new Padding(1); }
    protected override void OnResize(EventArgs e) { base.OnResize(e); UpdateRegion(); }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        if (Width <= 1 || Height <= 1) return;
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using GraphicsPath path = AdminGeometry.Rounded(new Rectangle(0, 0, Width - 1, Height - 1), CornerRadius);
        using var pen = new Pen(BorderColor, 1);
        e.Graphics.DrawPath(pen, path);
    }
    private void UpdateRegion()
    {
        if (Width <= 1 || Height <= 1) return;
        using GraphicsPath path = AdminGeometry.Rounded(new Rectangle(0, 0, Width, Height), CornerRadius);
        Region? old = Region; Region = new Region(path); old?.Dispose();
    }
}

internal sealed class AdminCard : AdminFrame
{
    internal AdminCard() { CornerRadius = 16; BorderColor = Color.FromArgb(21, 61, 76); }
    protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); BorderColor = Color.FromArgb(31, 103, 119); Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); BorderColor = Color.FromArgb(21, 61, 76); Invalidate(); }
}

internal sealed class AdminSurface : Panel
{
    internal AdminSurface() { DoubleBuffered = true; ResizeRedraw = true; BackColor = Color.FromArgb(4, 10, 15); }
    protected override void OnPaintBackground(PaintEventArgs e)
    {
        using var gradient = new LinearGradientBrush(ClientRectangle, Color.FromArgb(4, 10, 15), Color.FromArgb(4, 17, 24), LinearGradientMode.Vertical);
        e.Graphics.FillRectangle(gradient, ClientRectangle);
        using var grid = new Pen(Color.FromArgb(10, 43, 239, 201), 1);
        for (int x = 0; x < Width; x += 32) e.Graphics.DrawLine(grid, x, 0, x, Height);
        for (int y = 0; y < Height; y += 32) e.Graphics.DrawLine(grid, 0, y, Width, y);
    }
}
