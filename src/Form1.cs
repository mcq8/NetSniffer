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

            comboBox1.DataSource = NetworkInterfaceInfo.GetInterfaces();
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
            dataGridView1.DataSource = ((ProgramFlows)((ListBox)sender).SelectedItem).TcpTableRecords.Values.ToList<Flow>();
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
            if (sn == null)
            {
                sn = new SocketSniffer(Iphlpapi, (NetworkInterfaceInfo)comboBox1.SelectedItem);
                button3.Enabled = true;
                tokenSource = new CancellationTokenSource();
                CancellationToken ct = tokenSource.Token;
                Task.Factory.StartNew(() =>
                {
                    while (!ct.IsCancellationRequested)
                    {
                        this.Invoke((MethodInvoker)(() => label1.Text = "Observed: " + sn.PacketsObserved));
                        this.Invoke((MethodInvoker)(() => label2.Text = "Captured: " + sn.PacketsCaptured));
                        if (sn.TokenSource.IsCancellationRequested)
                        {
                            MessageBox.Show(sn.Exception.Message);
                            this.Invoke(new MethodInvoker(() => button3_Click(sender, e)));
                        }
                        Thread.Sleep(1000);
                    }
                });
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            button3.Enabled = false;
            if (sn != null)
            {
                tokenSource.Cancel();
                tokenSource = null;
                sn.Dispose();
                sn = null;
            }
            button2.Enabled = true;
        }
    }
}
