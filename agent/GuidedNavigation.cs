using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace Vorken.Agent;

// Owner-drawn navigation avoids native Button fills, wrapped glyphs and stale focus borders.
internal sealed class GuidedNavButton : Button
{
    internal int Symbol { get; set; }
    internal bool Selected { get; set; }
    private bool _hover;
    internal GuidedNavButton()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        FlatStyle = FlatStyle.Flat; FlatAppearance.BorderSize = 0;
        BackColor = Color.FromArgb(11, 20, 33); Cursor = Cursors.Hand;
    }
    protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hover = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }
    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias;
        Color color = Selected ? Color.FromArgb(76, 169, 255) : _hover || Focused ? Color.FromArgb(229, 240, 255) : Color.FromArgb(174, 198, 231);
        g.Clear(Color.FromArgb(11, 20, 33));
        using var pen = new Pen(color, 1.7F) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
        g.TranslateTransform(12, (Height - 22) / 2F - 1);
        switch (Symbol)
        {
            case 0: g.DrawLines(pen, new[] {new Point(1,10),new Point(11,1),new Point(21,10)}); g.DrawLines(pen,new[]{new Point(4,8),new Point(4,21),new Point(9,21),new Point(9,14),new Point(14,14),new Point(14,21),new Point(19,21),new Point(19,8)}); break;
            case 1: g.DrawEllipse(pen,2,1,14,14); g.DrawLine(pen,15,14,22,21); break;
            case 2: g.DrawPolygon(pen,new[]{new Point(5,1),new Point(15,1),new Point(20,6),new Point(20,22),new Point(5,22)});g.DrawLines(pen,new[]{new Point(14,1),new Point(14,7),new Point(20,7)});g.DrawLine(pen,9,12,16,12);g.DrawLine(pen,9,17,16,17);break;
            case 3: g.DrawEllipse(pen,1,1,21,21);g.DrawLines(pen,new[]{new Point(11,5),new Point(11,12),new Point(16,12)});break;
            case 4: for(int y=2;y<19;y+=10)for(int x=2;x<19;x+=10)g.DrawRectangle(pen,x,y,7,7);break;
            case 5: g.DrawEllipse(pen,7,7,8,8); for(int i=0;i<8;i++){double a=i*Math.PI/4;g.DrawLine(pen,(float)(11+8*Math.Cos(a)),(float)(11+8*Math.Sin(a)),(float)(11+11*Math.Cos(a)),(float)(11+11*Math.Sin(a)));}g.DrawEllipse(pen,2,2,18,18);break;
            default:g.DrawArc(pen,2,1,18,19,180,180);g.DrawRectangle(pen,1,11,4,8);g.DrawRectangle(pen,18,11,4,8);g.DrawLines(pen,new[]{new Point(20,19),new Point(17,22),new Point(12,22)});break;
        }
        g.ResetTransform();
        TextRenderer.DrawText(g,Text,Font,new Rectangle(43,0,Width-49,Height-4),color,TextFormatFlags.Left|TextFormatFlags.VerticalCenter|TextFormatFlags.SingleLine|TextFormatFlags.NoPadding);
        if(Selected){using var active=new Pen(Color.FromArgb(37,104,255),3);g.DrawLine(active,5,Height-3,Width-5,Height-3);}
        else if(Focused){using var focus=new Pen(color,1){DashStyle=DashStyle.Dot};g.DrawLine(focus,8,Height-3,Width-8,Height-3);}
    }
}
