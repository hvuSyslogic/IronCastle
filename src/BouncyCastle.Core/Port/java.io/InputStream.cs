using System;

namespace org.bouncycastle.Port.java.io
{
    public abstract class InputStream
    {
        public virtual int read()
        {
            throw new NotImplementedException();
        }

        public virtual long skip(long l)
        {
            throw new NotImplementedException();
        }

        public virtual int read(byte[] b)
        {
            throw new NotImplementedException();
        }

        public virtual int read(byte[] b, int offset, int length) { return 0; }

        public virtual int available()
        {
            throw new NotImplementedException();
        }

        public virtual void close() { }

        public virtual void mark(int readlimit) { }

        public virtual void reset() { }

        public virtual bool markSupported()
        {
            throw new NotImplementedException();
        }

        public int Read()
        {
            throw new NotImplementedException();
        }

        internal int Read(byte[] b, int v1, int v2)
        {
            throw new NotImplementedException();
        }
    }
}
