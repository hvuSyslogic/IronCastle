using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace BouncyCastle.Core.Port.Extensions
{
   public static class StreamExtensions
    {
        public static int Read(this Stream s)
        {
            return s.ReadByte();
        }

        public static void WriteByte(this Stream s, int value)
        {
            s.WriteByte((byte)value);
        }
    }
}
