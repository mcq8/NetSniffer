﻿using System;
using System.IO;
using System.Text;

namespace NetSniffer.Outputs.PcapNg
{
    public abstract class BaseBlock : IBlock
    {
        protected static readonly byte[] EndOptionCode = { 0x00, 0x00 };
        protected static readonly byte[] EndOptionLength = { 0x00, 0x00 };

        protected static byte[] GetOptionBytes(int code, string value)
        {
            return GetOptionBytes(code, Encoding.UTF8.GetBytes(value));
        }

        protected static byte[] GetOptionBytes(int code, byte[] value)
        {
            byte[] optionData;

            var optionCode = BitConverter.GetBytes(code);
            var optionValueLength = BitConverter.GetBytes(value.Length);
            var optionValue = PadToMultipleOf(value, 4);

            using (var ms = new MemoryStream())
            {

                using (var writer = new BinaryWriter(ms))
                {
                    writer.Write(optionCode, 0, 2);
                    writer.Write(optionValueLength, 0, 2);
                    writer.Write(optionValue);
                }

                optionData = ms.ToArray();
            }

            return optionData;
        }

        protected static byte[] PadToMultipleOf(byte[] src, int pad)
        {
            int len = (src.Length + pad - 1) / pad * pad;
            var padded = new byte[len];
            src.CopyTo(padded, 0);

            return padded;
        }

        protected static void PadToMultipleOf(ref byte[] src, int pad)
        {
            int len = (src.Length + pad - 1) / pad * pad;
            Array.Resize(ref src, len);
        }

        public abstract byte[] GetBytes();
    }
}
