using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace Vorken.Agent;

// The content is clipped by a viewport rather than showing a light native scrollbar.
internal sealed class GuidedScrollHost : UserControl
{
    private readonly Panel _viewport = new() { Dock = DockStyle.Fill };
    private readonly GuidedScrollBar _bar = new() { Dock = DockStyle.Right, Width = 12, TabStop = true, AccessibleName = "Rolagem das ferramentas", AccessibleRole = AccessibleRole.ScrollBar };
    internal FlowLayoutPanel Content { get; } = new() { FlowDirection = FlowDirection.LeftToRight, WrapContents = true, AutoScroll = false, BackColor = Color.Transparent, Padding = new Padding(0, 0, 0, 8) };
    private int _offset;
    private bool _layingOut;
    internal GuidedScrollHost()
    {
        BackColor = Color.FromArgb(11, 17, 27); _viewport.BackColor = BackColor;
        Controls.Add(_viewport); Controls.Add(_bar); _viewport.Controls.Add(Content);
        _bar.Changed += value => MoveTo(value); Content.Layout += (_, _) => Reflow();
        _viewport.Resize += (_, _) => Reflow(); Content.MouseWheel += Wheel; _viewport.MouseWheel += Wheel;
        Content.ControlAdded += (_, e) => HookFocus(e.Control!);
    }
    private void HookFocus(Control control)
    {
        control.Enter += (_, _) =>
        {
            if (control.IsDisposed || !control.Focused) return;
            var point = Content.PointToClient(control.PointToScreen(Point.Empty));
            if (point.Y < _offset) MoveTo(point.Y);
            else if (point.Y + control.Height > _offset + _viewport.Height) MoveTo(point.Y + control.Height - _viewport.Height);
        };
        foreach (Control child in control.Controls) HookFocus(child);
    }
    private void Wheel(object? sender, MouseEventArgs e) { MoveTo(_offset - Math.Sign(e.Delta) * 96); if(e is HandledMouseEventArgs handled) handled.Handled=true; }
    protected override void OnMouseWheel(MouseEventArgs e) { Wheel(this, e); base.OnMouseWheel(e); }
    private void Reflow()
    {
        if (_layingOut || _viewport.Width < 1) return; _layingOut = true;
        try { Content.Width = _viewport.Width - 10; Content.Height = Math.Max(_viewport.Height, Content.GetPreferredSize(new Size(Content.Width, 0)).Height); _bar.Total = Content.Height; _bar.Page = _viewport.Height; _bar.Visible = Content.Height > _viewport.Height; MoveTo(_offset); }
        finally { _layingOut = false; }
    }
    private void MoveTo(int value) { _offset = Math.Clamp(value, 0, Math.Max(0, Content.Height - _viewport.Height)); Content.Top = -_offset; _bar.Value = _offset; _bar.Invalidate(); }
}

internal sealed class GuidedScrollBar : Control
{
    internal int Total { get; set; }
    internal int Page { get; set; }
    internal int Value { get; set; }
    internal event Action<int>? Changed;
    private int _dragY, _dragValue;
    private bool _dragging, _hover;
    internal GuidedScrollBar() { DoubleBuffered = true; ResizeRedraw = true; BackColor = Color.FromArgb(11,17,27); Cursor = Cursors.Hand; }
    private int ThumbHeight => Math.Min(Height, Math.Max(36, (int)(Height * Math.Min(1d, (double)Page / Math.Max(1, Total)))));
    private int ThumbTop => (int)((Height - ThumbHeight) * (double)Value / Math.Max(1, Total - Page));
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e); if (Width<4||Height<4) return; e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
        using var path=VorkenGeometry.CreateRoundedRectangle(new Rectangle(3,ThumbTop,Width-6,ThumbHeight),3);
        using var brush=new SolidBrush(_dragging||_hover||Focused?Color.FromArgb(83,153,237):Color.FromArgb(53,79,113));e.Graphics.FillPath(brush,path);
    }
    protected override void OnMouseEnter(EventArgs e){_hover=true;Invalidate();base.OnMouseEnter(e);}
    protected override void OnMouseLeave(EventArgs e){_hover=false;Invalidate();base.OnMouseLeave(e);}
    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e); if(e.Button!=MouseButtons.Left)return;Focus();
        if(e.Y>=ThumbTop&&e.Y<=ThumbTop+ThumbHeight){_dragging=true;_dragY=e.Y;_dragValue=Value;Capture=true;}
        else Changed?.Invoke(Value+(e.Y<ThumbTop?-Page:Page));Invalidate();
    }
    protected override void OnMouseMove(MouseEventArgs e){base.OnMouseMove(e);if(_dragging)Changed?.Invoke(_dragValue+(int)((e.Y-_dragY)*(double)Math.Max(0,Total-Page)/Math.Max(1,Height-ThumbHeight)));}
    protected override void OnMouseUp(MouseEventArgs e){base.OnMouseUp(e);_dragging=false;Capture=false;Invalidate();}
    protected override void OnMouseCaptureChanged(EventArgs e){base.OnMouseCaptureChanged(e);if(!Capture)_dragging=false;}
    protected override bool IsInputKey(Keys keyData)=>keyData is Keys.Up or Keys.Down or Keys.PageUp or Keys.PageDown or Keys.Home or Keys.End || base.IsInputKey(keyData);
    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);int? next=e.KeyCode switch {Keys.Up=>Value-40,Keys.Down=>Value+40,Keys.PageUp=>Value-Page,Keys.PageDown=>Value+Page,Keys.Home=>0,Keys.End=>Total-Page,_=>null};
        if(next.HasValue){Changed?.Invoke(next.Value);e.Handled=true;}
    }
}
