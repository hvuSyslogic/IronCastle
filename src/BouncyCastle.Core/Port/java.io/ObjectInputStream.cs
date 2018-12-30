using System;
using org.bouncycastle.Port.java.io;

namespace BouncyCastle.Core.Port.java.io
{
    public class ObjectInputStream : InputStream
    {
        public ObjectInputStream(InputStream stream)
        {
            throw new NotImplementedException();
        }

        public object readObject()
        {
            throw new NotImplementedException();
        }

        public virtual Type resolveClass(Type desc)
        {
            throw new NotImplementedException();
        }
    }
}