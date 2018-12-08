using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace BouncyCastle.Core.Port.Extensions
{
   public static class MemoryStreamExtensions
    {
        public static byte[] toByteArray(this MemoryStream ms)
        {
            return ms.ToArray();
        }
    }
}
