using System;
using System.Collections.Generic;
using System.IO;

namespace NetSniffer.Outputs.PcapNg
{
    /// <summary>
    /// Outputs files in PCAPNG file format
    /// https://tools.ietf.org/html/draft-tuexen-opswg-pcapng-00 
    /// </summary>
    public class PcapNgFileOutput : IOutput, IDisposable
    {
        private FileStream fileStream;
        private BinaryWriter writer;
        private List<NetworkInterfaceInfo> NetworkInterfaceInfoList = new List<NetworkInterfaceInfo>();

        public PcapNgFileOutput(string filename)
        {
            fileStream = new FileStream(filename, FileMode.Create, FileAccess.Write, FileShare.Read);
            writer = new BinaryWriter(this.fileStream);
            WriteHeader();
        }

        public void Output(TimestampedData timestampedData)
        {
            int index = NetworkInterfaceInfoList.IndexOf(timestampedData.NetworkInterface);
            if (index == -1)
            {
                var interfaceDescriptionBlock = new InterfaceDescriptionBlock(timestampedData.NetworkInterface);
                writer.Write(interfaceDescriptionBlock.GetBytes());
                NetworkInterfaceInfoList.Add(timestampedData.NetworkInterface);
            }


            var block = new EnhancedPacketBlock(timestampedData);
            writer.Write(block.GetBytes());
            writer.Flush();
        }

        public void Dispose()
        {
            if (writer != null)
            {
                writer.Close();
                writer.Dispose();
                writer = null;
            }
            if (fileStream != null)
            {
                fileStream.Close();
                fileStream.Dispose();
                fileStream = null;
            }

        }

        private void WriteHeader()
        {
            var sectionHeaderBlock = new SectionHeaderBlock();
            writer.Write(sectionHeaderBlock.GetBytes());
        }
    }
}
