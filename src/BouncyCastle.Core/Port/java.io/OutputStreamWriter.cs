using System;
using System.Collections.Generic;
using System.Text;
using org.bouncycastle.Port.java.io;

namespace BouncyCastle.Core.Port.java.io
{
    public class OutputStreamWriter
    {
        private ByteArrayOutputStream bout;
        private string v;

        public OutputStreamWriter(ByteArrayOutputStream bout, string v)
        {
            this.bout = bout;
            this.v = v;
        }

        public void write(object format)
        {
            throw new NotImplementedException();
        }

        public void close()
        {
            throw new NotImplementedException();
        }
    }
}
