using System.ComponentModel;
using System.Net;
using System.Net.Sockets;

namespace NetSniffer
{
    public class Flow
    {
        [DisplayName("Type")]
        public ProtocolType Type { get; set; }
        [DisplayName("Local Address")]
        public IPEndPoint LocalEndpoint { get; set; }
        [DisplayName("Remote Address")]
        public IPEndPoint RemoteEndpoint { get; set; }
        [DisplayName("Process ID")]
        public int ProcessId { get; set; }
        public Flow(ProtocolType type, IPEndPoint localIp, IPEndPoint remoteIp, int processId)
        {
            Type = type;
            LocalEndpoint = localIp;
            RemoteEndpoint = remoteIp;
            ProcessId = processId;
        }
    }
}
