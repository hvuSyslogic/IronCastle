using System;

namespace org.bouncycastle.Port.java.io
{
    public abstract class OutputStream
    {
        public virtual void write(int tag)
        {
            throw new NotImplementedException();
        }

        public virtual void write(byte[] bytes)
        {
            throw new NotImplementedException();
        }

        public virtual void write(byte[] result, int pos, int v)
        {
            throw new NotImplementedException();
        }

        public virtual void flush()
        {
            throw new NotImplementedException();
        }

        public virtual void close()
        {
            throw new NotImplementedException();
        }

        public virtual int size()
        {
            throw new NotImplementedException();
        }
    }
}
