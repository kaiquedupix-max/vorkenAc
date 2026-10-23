using System.Drawing;
using System.Windows.Forms;

namespace Vorken.Agent;

internal sealed partial class AgentMainForm
{
    private void ShowConsentView()
    {
        _surface.Controls.Clear(); _surface.Mode = AnimatedSurfaceMode.Idle; _surface.AutoScroll = true;
        _nav.Visible = true; _nav.Enabled = true; _headerStatus.Visible = false; SetActiveNav(0);
        var frame = new Panel { Dock = DockStyle.Fill, Padding = new Padding(24, 18, 24, 22), BackColor = Background };
        var root = new GuidedGrid { Dock = DockStyle.Fill, Padding = new Padding(24), ColumnCount = 1, RowCount = 2, BackColor = Surface };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 136)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var heading = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, ColumnCount = 1, BackColor = Color.Transparent };
        heading.RowStyles.Add(new RowStyle(SizeType.Absolute, 24)); heading.RowStyles.Add(new RowStyle(SizeType.Absolute, 64)); heading.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        heading.Controls.Add(GuidedLabel(L("VERIFICAÇÃO DE INTEGRIDADE", "VERIFICACIÓN DE INTEGRIDAD", "INTEGRITY VERIFICATION"), 10, Blue, FontStyle.Bold), 0, 0);
        heading.Controls.Add(GuidedLabel(L("Análise técnica com evidências", "Análisis técnico con evidencias", "Technical analysis with evidence"), 30, TextPrimary, FontStyle.Bold), 0, 1);
        heading.Controls.Add(GuidedLabel(L("Revise as categorias e inicie quando estiver pronto. Você acompanha cada etapa da verificação.", "Revise las categorías e inicie cuando esté listo. Siga cada etapa de la verificación.", "Review the categories and start when ready. Follow every verification step."), 12, TextSecondary), 0, 2);
        root.Controls.Add(heading, 0, 0);
        var columns = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Color.Transparent };
        columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 64)); columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 36));
        var categories = new GuidedGrid { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7, Padding = new Padding(22), Margin = new Padding(0, 0, 18, 0), BackColor = Background };
        categories.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        categories.Controls.Add(GuidedLabel(L("O que será analisado", "Qué se analizará", "What will be analyzed"), 15, TextPrimary, FontStyle.Bold), 0, 0);
        string[] titles = { L("Dispositivos USB e hardware", "Dispositivos USB y hardware", "USB devices and hardware"), L("Histórico de execução", "Historial de ejecución", "Execution history"), L("Downloads e origem dos arquivos", "Descargas y origen de archivos", "Downloads and file origins"), L("Processos, serviços e módulos", "Procesos, servicios y módulos", "Processes, services and modules"), L("Execução correlacionada", "Ejecución correlacionada", "Correlated execution"), L("Integridade do sistema", "Integridad del sistema", "System integrity") };
        string[] hints = { L("Histórico de conexão, dispositivos seriais e drivers.", "Historial de conexión, dispositivos seriales y drivers.", "Connection history, serial devices and drivers."), L("Prefetch, BAM, cache do sistema e atividade recente.", "Prefetch, BAM, caché del sistema y actividad reciente.", "Prefetch, BAM, system cache and recent activity."), L("Arquivos obtidos, assinaturas digitais e integridade.", "Archivos obtenidos, firmas digitales e integridad.", "Downloaded files, digital signatures and integrity."), L("Processos em execução, módulos carregados e injeções.", "Procesos activos, módulos cargados e inyecciones.", "Running processes, loaded modules and injections."), L("Linha do tempo e correlação dos eventos relevantes.", "Cronología y correlación de eventos relevantes.", "Timeline and correlation of relevant events."), L("Modificações, hooks e ambiente de execução.", "Modificaciones, hooks y entorno de ejecución.", "Modifications, hooks and the execution environment.") };
        for (int i = 0; i < 6; i++)
        {
            categories.RowStyles.Add(new RowStyle(SizeType.Percent, 100F/6));
            var row = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, BackColor = Color.Transparent, Padding = new Padding(0, 8, 0, 8) };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 48)); row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); row.RowStyles.Add(new RowStyle(SizeType.Percent, 50)); row.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            var icon = new GuidedIcon { Kind = i == 0 ? 2 : i == 1 ? 0 : 1, Dock = DockStyle.Fill }; row.Controls.Add(icon, 0, 0); row.SetRowSpan(icon, 2);
            row.Controls.Add(GuidedLabel(titles[i], 12, TextPrimary, FontStyle.Bold), 1, 0); row.Controls.Add(GuidedLabel(hints[i], 10.5F, TextSecondary), 1, 1); categories.Controls.Add(row, 0, i+1);
        }
        columns.Controls.Add(categories, 0, 0);
        var side = new GuidedGrid { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(24), BackColor = SurfaceAlt };
        side.RowStyles.Add(new RowStyle(SizeType.Absolute, 106)); side.RowStyles.Add(new RowStyle(SizeType.Absolute, 54)); side.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); side.RowStyles.Add(new RowStyle(SizeType.Absolute, 70)); side.RowStyles.Add(new RowStyle(SizeType.Absolute, 58)); side.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        side.Controls.Add(new PictureBox { Image = LoadBrandMark(), Dock = DockStyle.Fill, SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Transparent, Margin = new Padding(0, 0, 0, 12) }, 0, 0);
        side.Controls.Add(GuidedLabel(L("Sua privacidade vem primeiro", "Su privacidad es lo primero", "Your privacy comes first"), 17, TextPrimary, FontStyle.Bold), 0, 1);
        side.Controls.Add(GuidedLabel(L("A análise é sob demanda e só começa com seu consentimento.\n\nNão coletamos senhas, cookies, mensagens, fotos ou documentos pessoais.\n\nDispositivos USB são revisados pelas regras técnicas existentes. A presença de um pendrive, por si só, não indica trapaça.", "El análisis es bajo demanda y solo comienza con su consentimiento.\n\nNo recopilamos contraseñas, cookies, mensajes, fotos ni documentos personales.\n\nLa presencia de una unidad USB no indica trampas por sí sola.", "Analysis is on demand and only starts with your consent.\n\nWe do not collect passwords, cookies, messages, photos or personal documents.\n\nUSB devices follow existing technical rules. USB presence alone does not indicate cheating."), 11, TextSecondary), 0, 2);
        side.Controls.Add(GuidedLabel(_termsAccepted ? L("✓ Termos aceitos\nA coleta começa apenas ao clicar em iniciar.", "✓ Términos aceptados\nLa recopilación comienza al pulsar iniciar.", "✓ Terms accepted\nCollection starts only when you click start.") : L("Revise e aceite os termos antes de iniciar.", "Revise y acepte los términos antes de iniciar.", "Review and accept the terms before starting."), 10.5F, _termsAccepted ? Success : Warning), 0, 3);
        var start = GuidedButton(L("Iniciar análise  →", "Iniciar análisis  →", "Start analysis  →"), () => AcceptButton_Click(this, EventArgs.Empty), true); start.Dock = DockStyle.Fill; start.Margin = new Padding(0, 4, 0, 4); start.Enabled = _termsAccepted; side.Controls.Add(start, 0, 4);
        var links = new FlowLayoutPanel { Dock = DockStyle.Fill, BackColor = Color.Transparent };
        var privacy = new LinkLabel { Text = L("Privacidade", "Privacidad", "Privacy"), AutoSize = true, LinkColor = Blue, Margin = new Padding(0, 10, 24, 0) }; privacy.LinkClicked += (_, _) => OpenUrl(PrivacyUrl); links.Controls.Add(privacy);
        var terms = new LinkLabel { Text = L("Rever termos", "Revisar términos", "Review terms"), AutoSize = true, LinkColor = Blue, Margin = new Padding(0, 10, 0, 0) }; terms.LinkClicked += (_, _) => ShowTermsGate(); links.Controls.Add(terms); side.Controls.Add(links, 0, 5);
        columns.Controls.Add(side, 1, 0); root.Controls.Add(columns, 0, 1); frame.Controls.Add(root); _surface.Controls.Add(frame);
    }
}
