using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace Vorken.Agent;

internal sealed class GuidedNotice : Control
{
    internal string Title { get; set; } = "";
    internal string Description { get; set; } = "";
    internal bool Failure { get; set; }
    internal GuidedNotice() { DoubleBuffered = true; ResizeRedraw = true; }
    protected override void OnPaintBackground(PaintEventArgs e)
    {
        if(Parent is null){base.OnPaintBackground(e);return;}
        GuidedBackground.Paint(this, e.Graphics);
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;
        using var path=VorkenGeometry.CreateRoundedRectangle(new Rectangle(0,0,Width-1,Height-1),9);
        using var fill=new LinearGradientBrush(ClientRectangle,Failure?Color.FromArgb(49,29,38):Color.FromArgb(14,35,56),Failure?Color.FromArgb(34,25,34):Color.FromArgb(9,24,40),15F);
        g.FillPath(fill,path);using var border=new Pen(Failure?Color.FromArgb(135,56,62):Color.FromArgb(36,66,97));g.DrawPath(border,path);
        Color ink=Failure?Color.FromArgb(255,113,103):Color.FromArgb(81,169,255);using var pen=new Pen(ink,2.5F);
        int y=Height/2;
        if(Failure){g.DrawEllipse(pen,18,y-18,36,36);g.DrawLine(pen,29,y-7,43,y+7);g.DrawLine(pen,43,y-7,29,y+7);}
        else {g.DrawRectangle(pen,26,y-22,16,12);g.DrawRectangle(pen,21,y-10,26,31);g.DrawLine(pen,31,y-19,31,y-13);g.DrawLine(pen,37,y-19,37,y-13);}
        using var titleFont=new Font("Segoe UI",12,FontStyle.Bold);using var bodyFont=new Font("Segoe UI",10.5F);
        TextRenderer.DrawText(g,Title,titleFont,new Rectangle(72,12,Width-88,26),Failure?ink:Color.FromArgb(237,244,255),TextFormatFlags.SingleLine|TextFormatFlags.EndEllipsis);
        TextRenderer.DrawText(g,Description,bodyFont,new Rectangle(72,40,Width-88,Height-44),Color.FromArgb(169,194,228),TextFormatFlags.WordBreak);
    }
}

internal sealed class GuidedActionButton : Button
{
    internal bool Primary {get;set;}
    private bool _hover;
    internal GuidedActionButton(){SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.ResizeRedraw,true);FlatStyle=FlatStyle.Flat;FlatAppearance.BorderSize=0;Cursor=Cursors.Hand;}
    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e); if(Width<3||Height<3)return;
        var previous=Region;Region=null;previous?.Dispose();
    }
    protected override void OnPaintBackground(PaintEventArgs e)
    {
        if(Parent is null){e.Graphics.Clear(Color.FromArgb(9,24,40));return;}
        GuidedBackground.Paint(this, e.Graphics);
    }
    protected override void OnEnabledChanged(EventArgs e){base.OnEnabledChanged(e);Invalidate();}
    protected override void OnMouseEnter(EventArgs e){_hover=true;Invalidate();base.OnMouseEnter(e);}
    protected override void OnMouseLeave(EventArgs e){_hover=false;Invalidate();base.OnMouseLeave(e);}
    protected override void OnPaint(PaintEventArgs e)
    {
        var g=e.Graphics;GuidedBackground.Paint(this, g);g.SmoothingMode=SmoothingMode.AntiAlias;
        if(Width<4||Height<4)return;
        using var path=VorkenGeometry.CreateRoundedRectangle(new Rectangle(1,1,Width-3,Height-3),9);
        Color top=Primary?Color.FromArgb(39,111,255):Color.FromArgb(24,42,63),bottom=Primary?Color.FromArgb(22,83,232):Color.FromArgb(13,29,46);
        if(_hover&&Enabled){top=Primary?Color.FromArgb(66,134,255):Color.FromArgb(32,56,81);}
        if(!Enabled){top=Color.FromArgb(34,48,66);bottom=Color.FromArgb(22,35,51);}
        using var fill=new LinearGradientBrush(ClientRectangle,top,bottom,90F);g.FillPath(fill,path);
        using var border=new Pen(Primary&&Enabled?Color.FromArgb(58,125,255):Color.FromArgb(55,79,107),Focused?2:1);g.DrawPath(border,path);
        TextRenderer.DrawText(g,Text,Font,ClientRectangle,Enabled?Color.FromArgb(241,247,255):Color.FromArgb(133,151,174),TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter|TextFormatFlags.SingleLine);
    }
}

// Paint the ancestor surface directly: native Button background rendering does not
// reliably preserve a translated Graphics context across transparent layout panels.
internal static class GuidedBackground
{
    internal static void Paint(Control child, Graphics graphics)
    {
        var offset = new Point(child.Left, child.Top);
        var parent = child.Parent;
        while (parent is not null)
        {
            Color top, bottom; float angle;
            if (parent is GuidedGrid)
            {
                bool red = parent.BackColor.R > 35;
                top = red ? Color.FromArgb(47,31,40) : Color.FromArgb(12,29,47);
                bottom = red ? Color.FromArgb(34,24,32) : Color.FromArgb(6,18,29); angle = 28;
            }
            else if (parent is VorkenCard)
            { top = Color.FromArgb(13,31,49); bottom = Color.FromArgb(7,19,32); angle = 24; }
            else if (parent is AnimatedSurface)
            { top = Color.FromArgb(11,17,27); bottom = Color.FromArgb(16,28,47); angle = 90; }
            else
            {
                if (parent.BackColor.A == 255)
                { using var solid = new SolidBrush(parent.BackColor); graphics.FillRectangle(solid, child.ClientRectangle); return; }
                offset.Offset(parent.Left, parent.Top); parent = parent.Parent; continue;
            }
            var bounds = new Rectangle(-offset.X, -offset.Y, Math.Max(1,parent.Width), Math.Max(1,parent.Height));
            using var gradient = new LinearGradientBrush(bounds, top, bottom, angle);
            graphics.FillRectangle(gradient, child.ClientRectangle); return;
        }
        graphics.Clear(Color.FromArgb(11,20,33));
    }
}
