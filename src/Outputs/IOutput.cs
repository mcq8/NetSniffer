using System;

namespace NetSniffer.Outputs
{
    public interface IOutput : IDisposable
    {
        void Output(TimestampedData timestampedData);
    }
}
