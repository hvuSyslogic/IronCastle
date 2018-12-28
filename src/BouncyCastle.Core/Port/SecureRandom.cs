using System;
using org.bouncycastle.util.test;
using Random = org.bouncycastle.Port.java.util.Random;

namespace BouncyCastle.Core.Port
{
    public class SecureRandom : Random
    {
        public SecureRandom()
        {
            throw new NotImplementedException();
        }

        public SecureRandom(object o, FixedSecureRandom.DummyProvider dummyProvider)
        {
            throw new NotImplementedException();
        }

        public virtual void nextBytes(byte[] currentSeed)
        {
            throw new NotImplementedException();
        }


        public virtual void setSeed(byte[] getBytes)
        {
            throw new NotImplementedException();
        }

        public virtual byte[] generateSeed(int i)
        {
            throw new NotImplementedException();
        }

        public virtual void setSeed(long seed)
        {
            throw new NotImplementedException();
        }

        public virtual int nextInt(int v)
        {
            throw new NotImplementedException();
        }
    }
}
