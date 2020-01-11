using System;

namespace NetSniffer
{
    public class TimestampedData
    {
        public DateTime Timestamp { get; }
        public byte[] Data { get; }
        public ProgramFlows ProgramFlows { get; set; }

        public NetworkInterfaceInfo NetworkInterface { get; }

        public TimestampedData(DateTime timestamp, byte[] data, NetworkInterfaceInfo networkInterface)
        {
            Timestamp = timestamp;
            Data = data;
            NetworkInterface = networkInterface;
        }
    }
}
