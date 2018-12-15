using System;
using System.Collections.Generic;
using System.Text;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.pqc.crypto.xmss;

namespace BouncyCastle.Core.Port.java.util
{
  public static  class Collections
    {
        public static Set EMPTY_SET = new HashSet();

        public static Map<K, V> unmodifiableMap<K,V>(Map<K, V> trailers)
        {
            throw new NotImplementedException();
        }

        public static Set singleton(byte[] ipWithSubnetMask)
        {
            throw new NotImplementedException();
        }

        public static void shuffle(List coeffs, SecureRandom getSecureRandom)
        {
            throw new NotImplementedException();
        }

        public static List unmodifiableList(ArrayList arrayList)
        {
            throw new NotImplementedException();
        }

        internal static List unmodifiableList(List headers)
        {
            throw new NotImplementedException();
        }

        public static Map<string, object[]> synchronizedMap(HashMap<string, object[]> hashMap)
        {
            throw new NotImplementedException();
        }

        internal static Map<string, DefaultXMSSMTOid> unmodifiableMap(Map<string, DefaultXMSSMTOid> map)
        {
            throw new NotImplementedException();
        }
    }
}
