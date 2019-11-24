using NetSniffer.Outputs;
using NetSniffer.Outputs.PcapNg;
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace NetSniffer
{
    public class SocketSniffer : IDisposable
    {
        private readonly ConcurrentQueue<TimestampedData> outputQueue;
        private readonly ProgramFlowManager programFlowManager;
        private readonly NetworkInterfaceInfo networkInterface;

        public CancellationTokenSource TokenSource { get; private set; }
        public Exception Exception { get; private set; }
        public long PacketsObserved { get; private set; }
        public long PacketsCaptured { get; private set; }

        public SocketSniffer(ProgramFlowManager programFlowManager, NetworkInterfaceInfo networkInterface)
        {
            this.programFlowManager = programFlowManager;
            this.networkInterface = networkInterface;
            
            outputQueue = new ConcurrentQueue<TimestampedData>();
            TokenSource = new CancellationTokenSource();

            Task<Exception>[] tasks = new Task<Exception>[]
            {
                Task<Exception>.Factory.StartNew(Outputting),
                Task<Exception>.Factory.StartNew(Receiving)
            };
            Task.Factory.ContinueWhenAny(tasks, exception =>
            {
                if (exception.Result != null)
                {
                    TokenSource.Cancel();
                    Exception = exception.Result;
                }
            });
        }

        private bool ShouldOutput(TimestampedData timestampedData)
        {
            ProtocolType protocol = (ProtocolType)Convert.ToInt32(timestampedData.Data[9]);
            if (protocol == ProtocolType.Udp || protocol == ProtocolType.Tcp)
            {
                int ipHeaderLength = timestampedData.Data[0] & 0x0F;
                var sourceEndPoint = new IPEndPoint(BitConverter.ToUInt32(timestampedData.Data, 12), timestampedData.Data[ipHeaderLength * 4] * 256 + timestampedData.Data[ipHeaderLength * 4 + 1]);
                var destEndPoint = new IPEndPoint(BitConverter.ToUInt32(timestampedData.Data, 16), timestampedData.Data[ipHeaderLength * 4 + 2] * 256 + timestampedData.Data[ipHeaderLength * 4 + 3]);
                int port = networkInterface.IPAddress.Equals(sourceEndPoint.Address) ? sourceEndPoint.Port : destEndPoint.Port;

                programFlowManager.portLookup.TryGetValue(new Tuple<ProtocolType, int>(protocol, port), out ProgramFlows program);
                if (program == null)
                {
                    programFlowManager.Update();
                    programFlowManager.portLookup.TryGetValue(new Tuple<ProtocolType, int>(protocol, port), out program);
                    if (program == null)
                    {
                        return false;
                    }
                }

                if (protocol == ProtocolType.Udp)
                {
                    program.TcpTableRecords.TryGetValue(new Tuple<ProtocolType, int>(protocol, port), out Flow flow);
                    if (flow != null)
                    {
                        flow.RemoteEndpoint = (networkInterface.IPAddress.Equals(sourceEndPoint.Address)) ? destEndPoint : sourceEndPoint;
                    }
                }
                timestampedData.ProgramFlows = program;
                if (program.Capture != false)
                {
                    return true;

                }
            }
            return false;
        }

        private Exception Receiving()
        {
            Socket socket = null;
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                socket.Bind(new IPEndPoint(networkInterface.IPAddress, 0));
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), new byte[4]);

                byte[] bufferRaw = new byte[10000];
                while (!TokenSource.IsCancellationRequested)
                {
                    int ret = socket.Receive(bufferRaw);
                    var buffer = new byte[ret];
                    Buffer.BlockCopy(bufferRaw, 0, buffer, 0, ret);
                    outputQueue.Enqueue(new TimestampedData(DateTime.UtcNow, buffer));
                    this.PacketsObserved++;
                }
            }
            catch (Exception ex)
            {
                return ex;
            }
            finally
            {
                if (socket != null)
                {
                    socket.Close();
                }
            }
            return null;
        }

        private Exception Outputting()
        {
            IOutput output = null;
            try
            {
                output = new PcapNgFileOutput(networkInterface, "capture" + DateTime.Now.ToString("yyyy_MM_dd_HH_mm") + ".pcap");

                TimestampedData timestampedData;
                while (!TokenSource.IsCancellationRequested)
                {
                    while (outputQueue.TryDequeue(out timestampedData))
                    {
                        if (ShouldOutput(timestampedData))
                        {
                            output.Output(timestampedData);
                            this.PacketsCaptured++;
                        }
                    }
                    Thread.Sleep(100);
                }

            }
            catch (Exception ex)
            {
                return ex;
            }
            finally
            {
                if (output != null)
                {
                    output.Dispose();
                }
            }

            return null;
        }


        public void Dispose()
        {
            TokenSource.Cancel();
        }
    }

}
