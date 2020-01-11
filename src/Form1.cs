using System;
using System.Drawing;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NetSniffer
{
    public partial class Form1 : Form
    {
        private SocketSniffer sn;
        CancellationTokenSource tokenSource;
        private readonly ProgramFlowManager Iphlpapi;
        public Form1()
        {

            Iphlpapi = new ProgramFlowManager();
            InitializeComponent();

            listBox1.DrawItem += ListBox1_DrawItem;
            listBox1.DataSource = Iphlpapi.programFlowsList;
            var networkInterfaces = NetworkInterfaceInfo.GetInterfaces();
            comboBox1.DataSource = networkInterfaces;
            sn = new SocketSniffer(Iphlpapi);
            sn.Error += Sn_Error;
            sn.init(networkInterfaces);

        }

        private void Sn_Error(object sender, ErrorEventArgs e)
        {
            this.Invoke((MethodInvoker)(() => { MessageBox.Show(e.Error.Message); Close(); }));
        }

        private void ListBox1_DrawItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index > -1)
            {
                if (((ProgramFlows)listBox1.Items[e.Index]).Capture)
                    e.Graphics.FillRectangle(Brushes.Green, e.Bounds);
                else
                    e.Graphics.FillRectangle(Brushes.Red, e.Bounds);

                using (Brush textBrush = new SolidBrush(e.ForeColor))
                {
                    e.Graphics.DrawString(((ProgramFlows)listBox1.Items[e.Index]).ProcessName, e.Font, textBrush, e.Bounds.Location);
                }
            }
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            dataGridView1.DataSource = ((ProgramFlows)((ListBox)sender).SelectedItem).NetworkTableRecords.Values.ToList<Flow>();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            foreach (var programFlows in listBox1.SelectedItems)
            {
                ((ProgramFlows)programFlows).Capture = !((ProgramFlows)programFlows).Capture;
            }

            listBox1.Refresh();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            button2.Enabled = false;
            button3.Enabled = true;
            sn.startCapture();
            tokenSource = new CancellationTokenSource();
            CancellationToken ct = tokenSource.Token;
            Task.Factory.StartNew(() =>
            {
                while (!ct.IsCancellationRequested)
                {
                    this.Invoke((MethodInvoker)(() => label1.Text = "Observed: " + sn.PacketsObserved));
                    this.Invoke((MethodInvoker)(() => label2.Text = "Captured: " + sn.PacketsCaptured));
                    Thread.Sleep(1000);
                }
            });
        }

        private void button3_Click(object sender, EventArgs e)
        {
            button3.Enabled = false;
            sn.stopCapture();
            tokenSource.Cancel();
            tokenSource = null;
            button2.Enabled = true;
        }
    }
}
