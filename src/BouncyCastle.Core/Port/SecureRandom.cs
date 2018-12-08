using System;
using System.Collections.Generic;
using System.Text;

namespace BouncyCastle.Core.Port
{
    public class SecureRandom
    {
        public void nextBytes(byte[] currentSeed)
        {
            
        }

        public int nextInt()
        {
            throw new NotImplementedException();
        }

        public void setSeed(byte[] getBytes)
        {
            throw new NotImplementedException();
        }

        public long nextLong()
        {
            throw new NotImplementedException();
        }

        public byte[] generateSeed(int i)
        {
            throw new NotImplementedException();
        }

        internal void setSeed(long seed)
        {
            throw new NotImplementedException();
        }
    }
}
