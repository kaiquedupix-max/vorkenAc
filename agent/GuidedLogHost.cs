using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Vorken.Agent;

internal sealed class GuidedLogHost : UserControl
{
    private readonly RichTextBox _box;
    private readonly GuidedScrollBar _bar = new() { Dock = DockStyle.Right, Width = 12, TabStop = true, AccessibleRole = AccessibleRole.ScrollBar, AccessibleName = "Rolagem do registro" };
    internal GuidedLogHost(RichTextBox box)
    {
        _box = box; BackColor = box.BackColor;
        box.ScrollBars = RichTextBoxScrollBars.None; box.Dock = DockStyle.Fill;
        Controls.Add(box); Controls.Add(_bar);
        _bar.Changed += ScrollTo; box.VScroll += RefreshBar; box.TextChanged += RefreshBar; box.Resize += RefreshBar;
        Disposed += (_, _) => { box.VScroll -= RefreshBar; box.TextChanged -= RefreshBar; box.Resize -= RefreshBar; };
    }
    private void RefreshBar(object? sender, EventArgs e)
    {
        if (!_box.IsHandleCreated || _box.IsDisposed) return;
        _bar.Total = _box.GetLineFromCharIndex(_box.TextLength) + 1;
        _bar.Page = Math.Max(1, _box.ClientSize.Height / Math.Max(1, _box.Font.Height));
        _bar.Value = (int)SendMessage(_box.Handle, 0x00ce, IntPtr.Zero, IntPtr.Zero);
        _bar.Visible = _bar.Total > _bar.Page; _bar.Invalidate();
    }
    private void ScrollTo(int value)
    {
        int first = (int)SendMessage(_box.Handle, 0x00ce, IntPtr.Zero, IntPtr.Zero);
        SendMessage(_box.Handle, 0x00b6, IntPtr.Zero, (IntPtr)(Math.Clamp(value, 0, Math.Max(0, _bar.Total - _bar.Page)) - first));
        RefreshBar(this, EventArgs.Empty);
    }
    [DllImport("user32.dll")] private static extern IntPtr SendMessage(IntPtr handle, uint message, IntPtr wParam, IntPtr lParam);
}
