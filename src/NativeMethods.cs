using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NetSniffer
{
    class NativeMethods
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetExtendedTcpTable(IntPtr pTcpTable, out int pdwSize, bool bOrder, AddressFamily ulAf, _TCP_TABLE_CLASS TableClass, int Reserved);

        [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, AddressFamily ulAf, _UDP_TABLE_CLASS tableClass, uint reserved = 0);

        public enum _TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        public enum _UDP_TABLE_CLASS
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
            SizeConst = 1)]
        public _MIB_TCPROW_OWNER_PID[] table;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _MIB_TCPROW_OWNER_PID
    {
        public IPEndPoint LocalIPEndPoint { get { return new IPEndPoint(dwLocalAddr, ConvertPort(dwLocalPort)); } }
        public IPEndPoint RemoteIPEndPoint { get { return new IPEndPoint(dwRemoteAddr, ConvertPort(dwRemotePort)); } }
        private int ConvertPort(byte[] dwPort)
        {
            return BitConverter.ToUInt16(new byte[2] {
                            dwPort[1],
                            dwPort[0] }, 0);
        }
        public int dwState;
        public uint dwLocalAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] dwLocalPort;
        public uint dwRemoteAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] dwRemotePort;
        public int dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _MIB_UDPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
            SizeConst = 1)]
        public _MIB_UDPROW_OWNER_PID[] table;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _MIB_UDPROW_OWNER_PID
    {
        public IPEndPoint IPEndPoint { get { return new IPEndPoint(dwLocalAddr, ConvertPort(dwLocalPort)); } }

        private int ConvertPort(byte[] dwPort)
        {
            return BitConverter.ToUInt16(new byte[2] {
                            dwPort[1],
                            dwPort[0] }, 0);
        }
        public uint dwLocalAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] dwLocalPort;
        public int dwOwningPid;
    }
}
