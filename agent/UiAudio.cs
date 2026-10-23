using System.Media;

namespace Vorken.Agent;

internal sealed class UiAudio : IDisposable
{
    private readonly SoundPlayer _hover = Load("hover");
    private readonly SoundPlayer _click = Load("click");
    private long _lastHover;

    private static SoundPlayer Load(string name)
    {
        var stream = typeof(UiAudio).Assembly.GetManifestResourceStream($"Vorken.Agent.assets.ui-{name}.wav")
            ?? throw new InvalidOperationException("Som da interface ausente: " + name);
        var player = new SoundPlayer(stream);
        player.Load();
        return player;
    }

    internal void Hover()
    {
        long now = Environment.TickCount64;
        if (now - _lastHover < 110) return;
        _lastHover = now;
        Play(_hover);
    }

    internal void Click() => Play(_click);

    private static void Play(SoundPlayer player)
    {
        try { player.Play(); }
        catch (System.ComponentModel.Win32Exception) { }
        catch (InvalidOperationException) { }
    }

    public void Dispose()
    {
        _hover.Stop(); _click.Stop();
        _hover.Stream?.Dispose(); _click.Stream?.Dispose();
        _hover.Dispose(); _click.Dispose();
    }
}
