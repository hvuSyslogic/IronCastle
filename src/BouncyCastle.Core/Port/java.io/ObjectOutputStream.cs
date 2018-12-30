using System;
using System.Collections.Generic;
using System.Text;
using org.bouncycastle.Port.java.io;

namespace BouncyCastle.Core.Port.java.io
{
    public class ObjectOutputStream : OutputStream
    {
        public ObjectOutputStream(OutputStream stream)
        {
            throw new NotImplementedException();
        }

        public void writeObject(object o)
        {
            throw new NotImplementedException();
        }
    }
}
