using System.Drawing.Imaging;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Vorken.Agent;

internal sealed record RemoteAdministrator(long Id, string DisplayName)
{
    public override string ToString() => DisplayName;
}

internal sealed class RemoteSupportClient : IAsyncDisposable
{
    private readonly AgentConfig _config;
    private readonly HttpClient _http;
    private readonly CancellationTokenSource _lifetime = new();
    private ClientWebSocket? _socket;
    private string? _sessionId;
    private bool _controlEnabled;

    public bool IsActive { get; private set; }

    public RemoteSupportClient(AgentConfig config)
    {
        _config = config;
        _http = new HttpClient
        {
            BaseAddress = new Uri(config.ServerUrl.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(30)
        };
    }

    public async Task<List<RemoteAdministrator>> GetAvailableAdminsAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _http.GetFromJsonAsync<AdminsResponse>(
            $"api/agent/{Uri.EscapeDataString(_config.Token)}/remote/admins", cancellationToken);
        return payload?.Admins ?? [];
    }

    public async Task RunAsync(long adminId, string mode, Action<string> status, CancellationToken cancellationToken = default)
    {
        if (IsActive) throw new InvalidOperationException("Já existe uma transmissão ativa.");
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        var request = await _http.PostAsJsonAsync(
            $"api/agent/{Uri.EscapeDataString(_config.Token)}/remote/sessions",
            new { adminId, mode }, linked.Token);
        request.EnsureSuccessStatusCode();
        var created = await request.Content.ReadFromJsonAsync<CreateSessionResponse>(cancellationToken: linked.Token)
            ?? throw new InvalidOperationException("Resposta inválida do servidor.");
        _sessionId = created.SessionId;
        _controlEnabled = mode == "control";
        status("Solicitação enviada. Aguardando o administrador aceitar...");

        while (!linked.IsCancellationRequested)
        {
            await Task.Delay(1200, linked.Token);
            var state = await _http.GetFromJsonAsync<SessionState>(
                $"api/agent/{Uri.EscapeDataString(_config.Token)}/remote/sessions/{Uri.EscapeDataString(created.SessionId)}",
                linked.Token);
            if (state?.Status == "accepted") break;
            if (state?.Status is "rejected" or "ended")
                throw new InvalidOperationException("O administrador recusou ou encerrou a solicitação.");
            if (state is null || DateTimeOffset.UtcNow >= created.ExpiresAt)
                throw new TimeoutException("A solicitação expirou sem resposta.");
        }

        IsActive = true;
        try
        {
            try
            {
                _socket = new ClientWebSocket();
                await _socket.ConnectAsync(new Uri(created.WebSocketUrl), linked.Token);
                await SendTextAsync(JsonSerializer.Serialize(new
                {
                    type = "authenticate", role = "agent", sessionId = created.SessionId, secret = created.AgentSecret
                }), linked.Token);
                status(_controlEnabled
                    ? "TELA + CONTROLE ativos. Clique em PARAR a qualquer momento."
                    : "TRANSMISSÃO DE TELA ativa. Clique em PARAR a qualquer momento.");
                Task receive = ReceiveControlsAsync(linked.Token);
                Task capture = CaptureLoopAsync(linked.Token);
                Task completed = await Task.WhenAny(receive, capture);
                await completed;
            }
            catch (Exception ex) when (
                (ex is WebSocketException or HttpRequestException or InvalidOperationException) &&
                !linked.IsCancellationRequested)
            {
                _socket?.Dispose();
                _socket = null;
                status(_controlEnabled
                    ? "TELA + CONTROLE ativos pelo modo HTTPS compatível."
                    : "TRANSMISSÃO DE TELA ativa pelo modo HTTPS compatível.");
                Task receive = PollHttpControlsAsync(created, linked.Token);
                Task capture = CaptureHttpLoopAsync(created, linked.Token);
                Task completed = await Task.WhenAny(receive, capture);
                await completed;
            }
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested) { }
        finally
        {
            IsActive = false;
            status("Transmissão encerrada.");
        }
    }

    public async Task StopAsync()
    {
        string? id = _sessionId;
        _lifetime.Cancel();
        if (_socket is { State: WebSocketState.Open })
        {
            try { await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Encerrada pelo jogador", CancellationToken.None); }
            catch { }
        }
        if (!string.IsNullOrWhiteSpace(id))
        {
            try
            {
                await _http.PostAsync(
                    $"api/agent/{Uri.EscapeDataString(_config.Token)}/remote/sessions/{Uri.EscapeDataString(id)}/end",
                    null);
            }
            catch { }
        }
        IsActive = false;
    }

    private async Task CaptureLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && _socket?.State == WebSocketState.Open)
        {
            byte[] frame = CaptureJpeg();
            await _socket.SendAsync(frame, WebSocketMessageType.Binary, true, cancellationToken);
            await Task.Delay(240, cancellationToken);
        }
    }

    private async Task CaptureHttpLoopAsync(CreateSessionResponse session, CancellationToken cancellationToken)
    {
        string path = $"api/agent/{Uri.EscapeDataString(_config.Token)}/remote/sessions/{Uri.EscapeDataString(session.SessionId)}/frame";
        while (!cancellationToken.IsCancellationRequested)
        {
            byte[] frame = CaptureJpeg();
            using var request = new HttpRequestMessage(HttpMethod.Post, path);
            request.Headers.Add("X-Vorken-Session-Secret", session.AgentSecret);
            request.Content = new ByteArrayContent(frame);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("image/jpeg");
            using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();
            await Task.Delay(280, cancellationToken);
        }
    }

    private async Task PollHttpControlsAsync(CreateSessionResponse session, CancellationToken cancellationToken)
    {
        long sequence = 0;
        string basePath = $"api/agent/{Uri.EscapeDataString(_config.Token)}/remote/sessions/{Uri.EscapeDataString(session.SessionId)}/input";
        while (!cancellationToken.IsCancellationRequested)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{basePath}?after={sequence}");
            request.Headers.Add("X-Vorken-Session-Secret", session.AgentSecret);
            using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();
            var payload = await response.Content.ReadFromJsonAsync<InputEventsResponse>(cancellationToken: cancellationToken);
            foreach (InputEvent item in payload?.Events ?? [])
            {
                sequence = Math.Max(sequence, item.Sequence);
                if (_controlEnabled) RemoteInput.Apply(item.Event);
            }
            await Task.Delay(90, cancellationToken);
        }
    }

    private static byte[] CaptureJpeg()
    {
        Rectangle screen = SystemInformation.VirtualScreen;
        const int maxWidth = 1280;
        int width = Math.Min(maxWidth, screen.Width);
        int height = Math.Max(1, (int)Math.Round(screen.Height * (width / (double)screen.Width)));
        using var scaled = new Bitmap(width, height, PixelFormat.Format24bppRgb);
        using (Graphics graphics = Graphics.FromImage(scaled))
        {
            IntPtr source = GetDC(IntPtr.Zero);
            IntPtr destination = graphics.GetHdc();
            try
            {
                SetStretchBltMode(destination, 4);
                StretchBlt(destination, 0, 0, width, height,
                    source, screen.Left, screen.Top, screen.Width, screen.Height,
                    0x00CC0020u | 0x40000000u);
            }
            finally
            {
                graphics.ReleaseHdc(destination);
                ReleaseDC(IntPtr.Zero, source);
            }
        }
        using var output = new MemoryStream();
        ImageCodecInfo codec = ImageCodecInfo.GetImageEncoders().First(x => x.MimeType == "image/jpeg");
        using var parameters = new EncoderParameters(1);
        parameters.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 55L);
        scaled.Save(output, codec, parameters);
        return output.ToArray();
    }

    private async Task ReceiveControlsAsync(CancellationToken cancellationToken)
    {
        if (_socket is null) return;
        byte[] buffer = new byte[16 * 1024];
        while (!cancellationToken.IsCancellationRequested && _socket.State == WebSocketState.Open)
        {
            WebSocketReceiveResult result = await _socket.ReceiveAsync(buffer, cancellationToken);
            if (result.MessageType == WebSocketMessageType.Close) break;
            if (result.MessageType != WebSocketMessageType.Text || !_controlEnabled) continue;
            try
            {
                using JsonDocument document = JsonDocument.Parse(buffer.AsMemory(0, result.Count));
                RemoteInput.Apply(document.RootElement);
            }
            catch { }
        }
    }

    private Task SendTextAsync(string text, CancellationToken cancellationToken) =>
        _socket!.SendAsync(Encoding.UTF8.GetBytes(text), WebSocketMessageType.Text, true, cancellationToken);

    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr window);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr window, IntPtr deviceContext);
    [DllImport("gdi32.dll")] private static extern int SetStretchBltMode(IntPtr deviceContext, int mode);
    [DllImport("gdi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StretchBlt(
        IntPtr destination, int xDestination, int yDestination, int destinationWidth, int destinationHeight,
        IntPtr source, int xSource, int ySource, int sourceWidth, int sourceHeight, uint rasterOperation);

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _socket?.Dispose();
        _http.Dispose();
        _lifetime.Dispose();
    }

    private sealed class AdminsResponse { public List<RemoteAdministrator> Admins { get; set; } = []; }
    private sealed class CreateSessionResponse
    {
        public string SessionId { get; set; } = "";
        public string AgentSecret { get; set; } = "";
        public string WebSocketUrl { get; set; } = "";
        public DateTimeOffset ExpiresAt { get; set; }
    }
    private sealed class SessionState { public string Status { get; set; } = ""; }
    private sealed class InputEventsResponse { public List<InputEvent> Events { get; set; } = []; }
    private sealed class InputEvent { public long Sequence { get; set; } public JsonElement Event { get; set; } }
}

internal static class RemoteInput
{
    private const uint InputMouse = 0;
    private const uint InputKeyboard = 1;
    private const uint MouseMove = 0x0001;
    private const uint MouseAbsolute = 0x8000;
    private const uint MouseVirtualDesktop = 0x4000;
    private const uint MouseLeftDown = 0x0002;
    private const uint MouseLeftUp = 0x0004;
    private const uint MouseRightDown = 0x0008;
    private const uint MouseRightUp = 0x0010;
    private const uint KeyUp = 0x0002;

    public static void Apply(JsonElement message)
    {
        string type = message.TryGetProperty("type", out var typeValue) ? typeValue.GetString() ?? "" : "";
        if (type == "pointer")
        {
            double x = Math.Clamp(message.GetProperty("x").GetDouble(), 0, 1);
            double y = Math.Clamp(message.GetProperty("y").GetDouble(), 0, 1);
            SendMouse((int)(x * 65535), (int)(y * 65535), MouseMove | MouseAbsolute | MouseVirtualDesktop);
            string action = message.TryGetProperty("action", out var a) ? a.GetString() ?? "" : "";
            uint flags = action switch
            {
                "leftDown" => MouseLeftDown, "leftUp" => MouseLeftUp,
                "rightDown" => MouseRightDown, "rightUp" => MouseRightUp,
                _ => 0
            };
            if (flags != 0) SendMouse(0, 0, flags);
        }
        else if (type == "key" && message.TryGetProperty("keyCode", out var keyValue))
        {
            int keyCode = keyValue.GetInt32();
            if (keyCode is >= 8 and <= 255)
                SendKey((ushort)keyCode, message.TryGetProperty("up", out var up) && up.GetBoolean());
        }
    }

    private static void SendMouse(int x, int y, uint flags)
    {
        INPUT input = new() { type = InputMouse, union = new InputUnion { mouse = new MOUSEINPUT { dx = x, dy = y, flags = flags } } };
        SendInput(1, [input], Marshal.SizeOf<INPUT>());
    }
    private static void SendKey(ushort key, bool up)
    {
        INPUT input = new() { type = InputKeyboard, union = new InputUnion { keyboard = new KEYBDINPUT { virtualKey = key, flags = up ? KeyUp : 0 } } };
        SendInput(1, [input], Marshal.SizeOf<INPUT>());
    }

    [StructLayout(LayoutKind.Sequential)] private struct INPUT { public uint type; public InputUnion union; }
    [StructLayout(LayoutKind.Explicit)] private struct InputUnion { [FieldOffset(0)] public MOUSEINPUT mouse; [FieldOffset(0)] public KEYBDINPUT keyboard; }
    [StructLayout(LayoutKind.Sequential)] private struct MOUSEINPUT { public int dx, dy; public uint mouseData, flags, time; public IntPtr extraInfo; }
    [StructLayout(LayoutKind.Sequential)] private struct KEYBDINPUT { public ushort virtualKey, scanCode; public uint flags, time; public IntPtr extraInfo; }
    [DllImport("user32.dll", SetLastError = true)] private static extern uint SendInput(uint count, INPUT[] inputs, int size);
}
