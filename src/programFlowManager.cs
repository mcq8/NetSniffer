using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace NetSniffer
{
    public class ProgramFlowManager
    {
        public ThreadedBindingList<ProgramFlows> programFlowsList { get; } = new ThreadedBindingList<ProgramFlows>();
        public Dictionary<string, ProgramFlows> programFlows { get; } = new Dictionary<string, ProgramFlows>();
        public Dictionary<Tuple<ProtocolType, int>, ProgramFlows> portLookup { get; } = new Dictionary<Tuple<ProtocolType, int>, ProgramFlows>();
        private Dictionary<int, string> programIdCache { get; } = new Dictionary<int, string>();

        public ProgramFlowManager()
        {
            Task.Factory.StartNew(() =>
            {
                while (true)
                {
                    Update();
                    Thread.Sleep(1000);
                }
            });

        }

        public void Update()
        {
            List<Flow> flows = GetFlows();
            foreach (Flow flow in flows)
            {
                if (flow.ProcessId == 0)
                {
                    continue;
                }

                programIdCache.TryGetValue(flow.ProcessId, out string ProcessName);
                if (ProcessName == null)
                {
                    try
                    {
                        ProcessName = Process.GetProcessById(flow.ProcessId).ProcessName;
                        programIdCache.Add(flow.ProcessId, ProcessName);
                    }
                    catch (Exception)
                    {
                        continue;
                    }
                }

                programFlows.TryGetValue(ProcessName, out ProgramFlows program);
                if (program == null)
                {
                    program = new ProgramFlows(ProcessName);

                    programFlows.Add(program.ProcessName, program);
                    programFlowsList.Add(program);
                }
                Tuple<ProtocolType, int> protocolport = new Tuple<ProtocolType, int>(flow.Type, flow.LocalEndpoint.Port);
                if (!program.TcpTableRecords.ContainsKey(protocolport))
                {
                    program.TcpTableRecords.Add(protocolport, flow);
                    try
                    {
                        portLookup.Add(protocolport, program);

                    }
                    catch (Exception)
                    {

                    }
                }
            }
        }

        private static List<Flow> GetFlows()
        {
            List<Flow> flows = new List<Flow>();
            _ = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, out int bufferSize, true, AddressFamily.InterNetwork, NativeMethods._TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_ALL, 0);
            IntPtr tcpTableRecordsPtr = Marshal.AllocHGlobal(bufferSize);
            _ = NativeMethods.GetExtendedTcpTable(tcpTableRecordsPtr, out bufferSize, true, AddressFamily.InterNetwork, NativeMethods._TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            _MIB_TCPTABLE_OWNER_PID tcpRecordsTable = (_MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(tcpTableRecordsPtr, typeof(_MIB_TCPTABLE_OWNER_PID));
            IntPtr tableRowPtr = tcpTableRecordsPtr + Marshal.SizeOf(tcpRecordsTable.dwNumEntries);

            for (int row = 0; row < tcpRecordsTable.dwNumEntries; row++)
            {
                _MIB_TCPROW_OWNER_PID tcpRow = (_MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(tableRowPtr, typeof(_MIB_TCPROW_OWNER_PID));
                Flow flow = new Flow(
                    ProtocolType.Tcp,
                    tcpRow.LocalIPEndPoint,
                    tcpRow.RemoteIPEndPoint,
                    tcpRow.dwOwningPid);
                flows.Add(flow);
                tableRowPtr += Marshal.SizeOf(tcpRow);
            }
            Marshal.FreeHGlobal(tcpTableRecordsPtr);

            bufferSize = 0;
            _ = NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AddressFamily.InterNetwork, NativeMethods._UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
            IntPtr udpTableRecordPtr = Marshal.AllocHGlobal(bufferSize);
            _ = NativeMethods.GetExtendedUdpTable(udpTableRecordPtr, ref bufferSize, true, AddressFamily.InterNetwork, NativeMethods._UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);

            _MIB_UDPTABLE_OWNER_PID udpRecordsTable = (_MIB_UDPTABLE_OWNER_PID)Marshal.PtrToStructure(udpTableRecordPtr, typeof(_MIB_UDPTABLE_OWNER_PID));
            tableRowPtr = udpTableRecordPtr + Marshal.SizeOf(udpRecordsTable.dwNumEntries);
            for (int row = 0; row < udpRecordsTable.dwNumEntries; row++)
            {
                _MIB_UDPROW_OWNER_PID udpRow = (_MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(tableRowPtr, typeof(_MIB_UDPROW_OWNER_PID));

                Flow flow = new Flow(
                      ProtocolType.Udp,
                      udpRow.IPEndPoint,
                      new IPEndPoint(0, 0),
                      udpRow.dwOwningPid);
                flows.Add(flow);

                tableRowPtr += Marshal.SizeOf(udpRow);
            }
            Marshal.FreeHGlobal(udpTableRecordPtr);

            return flows;
        }
    }
}
