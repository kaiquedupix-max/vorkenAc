using System.Drawing;
using System.Windows.Forms;

namespace Vorken.Agent;

internal sealed class GuidedComboBox : ComboBox
{
    internal GuidedComboBox()
    {
        DrawMode=DrawMode.OwnerDrawFixed;ItemHeight=30;FlatStyle=FlatStyle.Flat;
        BackColor=Color.FromArgb(12,29,47);ForeColor=Color.FromArgb(232,241,255);
        AccessibleName="Administrador disponível";
    }
    protected override void OnDrawItem(DrawItemEventArgs e)
    {
        bool selected=(e.State&DrawItemState.Selected)!=0;
        using var brush=new SolidBrush(selected?Color.FromArgb(26,64,109):BackColor);e.Graphics.FillRectangle(brush,e.Bounds);
        string text=e.Index>=0&&e.Index<Items.Count?(GetItemText(Items[e.Index])??""):"";
        TextRenderer.DrawText(e.Graphics,text,Font,new Rectangle(e.Bounds.X+10,e.Bounds.Y,e.Bounds.Width-16,e.Bounds.Height),ForeColor,TextFormatFlags.VerticalCenter|TextFormatFlags.SingleLine|TextFormatFlags.EndEllipsis);
    }
    protected override void WndProc(ref Message m)
    {
        base.WndProc(ref m);
        if(m.Msg!=0x000f||!IsHandleCreated||Width<24)return;
        using var g=Graphics.FromHwnd(Handle);using var fill=new SolidBrush(BackColor);using var pen=new Pen(Color.FromArgb(73,110,155));
        g.FillRectangle(fill,Width-25,1,24,Height-2);g.DrawRectangle(pen,0,0,Width-1,Height-1);
        int x=Width-14,y=Height/2;g.DrawLines(pen,new[]{new Point(x-4,y-2),new Point(x,y+2),new Point(x+4,y-2)});
    }
}
