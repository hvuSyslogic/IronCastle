using System;
using System.Collections.Generic;
using org.bouncycastle.util;

namespace org.bouncycastle.Port.java.util
{
    public class Arrays
    {
        //NOTE: This is not correct, but it will do for this port
        public static string asList<T>(T[] list)
        {
            return string.Join(",", list);
        }

        public IEnumerable<T> Iterator<T>()
        {
            throw new NotImplementedException();
        }

        internal static string ToString(byte[] oid)
        {
            throw new NotImplementedException();
        }
    }
}
