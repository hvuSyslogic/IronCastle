using System;
using System.IO;

namespace org.bouncycastle.Port.java.io
{
    public class ByteArrayOutputStream : OutputStream
    {
        private MemoryStream ms = new MemoryStream();

        public ByteArrayOutputStream()
        {
            ms = new MemoryStream();
        }

        public ByteArrayOutputStream(int i)
        {
            ms = new MemoryStream();
            ms.SetLength(i); //TODO: is this right?
        }

        public byte[] buf
        {
            get { return ms.ToArray(); }
        }

        public byte[] toByteArray()
        {
            throw new NotImplementedException();
        }

        public int count()
        {
            return (int)ms.Length;
        }

        public void reset()
        {
            throw new NotImplementedException();
        }

        public void writeTo(OutputStream output)
        {
            throw new NotImplementedException();
        }

        public override void write(int tag)
        {
            throw new NotImplementedException();
        }

        public override void write(byte[] bytes)
        {
            throw new NotImplementedException();
        }

        public override void write(byte[] result, int pos, int v)
        {
            throw new NotImplementedException();
        }

        public override void flush()
        {
            throw new NotImplementedException();
        }

        public override void close()
        {
            throw new NotImplementedException();
        }

        public override int size()
        {
            throw new NotImplementedException();
        }
    }
}
