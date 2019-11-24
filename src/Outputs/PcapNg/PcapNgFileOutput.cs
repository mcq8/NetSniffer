using System;
using System.IO;

namespace NetSniffer.Outputs.PcapNg
{
    /// <summary>
    /// Outputs files in PCAPNG file format
    /// https://tools.ietf.org/html/draft-tuexen-opswg-pcapng-00 
    /// </summary>
    public class PcapNgFileOutput : IOutput, IDisposable
    {
        private readonly NetworkInterfaceInfo nic;
        private FileStream fileStream;
        private BinaryWriter writer;

        public PcapNgFileOutput(NetworkInterfaceInfo nic, string filename)
        {
            this.nic = nic;
            fileStream = new FileStream(filename, FileMode.Create, FileAccess.Write, FileShare.None);
            writer = new BinaryWriter(this.fileStream);
            WriteHeader();
        }

        public void Output(TimestampedData timestampedData)
        {
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

            var interfaceDescriptionBlock = new InterfaceDescriptionBlock(nic);
            writer.Write(interfaceDescriptionBlock.GetBytes());
        }
    }
}
