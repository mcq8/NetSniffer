using System;

namespace NetSniffer
{
    public class TimestampedData
    {
        public DateTime Timestamp { get; }
        public byte[] Data { get; }
        public ProgramFlows ProgramFlows { get; set; }

        public TimestampedData(DateTime timestamp, byte[] data)
        {
            this.Timestamp = timestamp;
            this.Data = data;

        }
    }
}
