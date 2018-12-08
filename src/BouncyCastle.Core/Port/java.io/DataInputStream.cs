using System;
using System.Collections.Generic;
using System.Text;
using org.bouncycastle.Port.java.io;

namespace BouncyCastle.Core.Port.java.io
{
   public  class DataInputStream
    {
        private InputStream @is;

        public DataInputStream(InputStream @is)
        {
            this.@is = @is;
        }

        public int readInt()
        {
            throw new NotImplementedException();
        }

        public bool readBoolean()
        {
            throw new NotImplementedException();
        }

        public void readFully(byte[] oid)
        {
            throw new NotImplementedException();
        }

        public int read()
        {
            throw new NotImplementedException();
        }

        public string readUTF()
        {
            throw new NotImplementedException();
        }

        internal void read(byte[] oid)
        {
            throw new NotImplementedException();
        }

        public double readDouble()
        {
            throw new NotImplementedException();
        }
    }
}
