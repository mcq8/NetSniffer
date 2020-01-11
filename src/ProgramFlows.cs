using System;
using System.Collections.Generic;
using System.Net.Sockets;

namespace NetSniffer
{
    public class ProgramFlows
    {
        public bool Capture { get; set; }
        public string ProcessName { get; set; }
        public Dictionary<Tuple<ProtocolType, int>, Flow> NetworkTableRecords { get; } = new Dictionary<Tuple<ProtocolType, int>, Flow>();

        public ProgramFlows(string processName)
        {
            ProcessName = processName;
            Capture = true;
        }

    }
}
