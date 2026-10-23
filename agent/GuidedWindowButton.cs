using System.Drawing.Drawing2D;

namespace Vorken.Agent;

internal sealed class GuidedWindowButton : Control
{
    internal int Kind { get; set; }
    private bool _hover;
    internal GuidedWindowButton()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
            ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.Opaque, true);
        AccessibleRole = AccessibleRole.PushButton;
        Cursor = Cursors.Hand;
    }
    protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hover = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Color.FromArgb(11, 20, 33));
        g.SmoothingMode = SmoothingMode.AntiAlias;
        using var pen = new Pen(_hover
            ? Kind == 2 ? Color.FromArgb(255, 119, 119) : Color.FromArgb(83, 168, 255)
            : Color.FromArgb(195, 214, 240), _hover ? 1.6F : 1.2F);
        int x = Width / 2, y = Height / 2;
        if (Kind == 2) { g.DrawLine(pen, x - 4, y - 4, x + 4, y + 4); g.DrawLine(pen, x + 4, y - 4, x - 4, y + 4); }
        else if (Kind == 1) g.DrawRectangle(pen, x - 4, y - 4, 8, 8);
        else g.DrawLine(pen, x - 5, y + 2, x + 5, y + 2);
    }
}
