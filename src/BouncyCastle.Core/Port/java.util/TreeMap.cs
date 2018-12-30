using System;
using System.Collections.Generic;
using System.Text;
using org.bouncycastle.pqc.crypto.xmss;
using org.bouncycastle.Port.java.util;

namespace BouncyCastle.Core.Port.java.util
{
    public class TreeMap<K, V> : Map<K, V>
    {
        public TreeMap()
        {

        }

        public TreeMap(Map<int, XMSSNode> lastKeep)
        {
            throw new NotImplementedException();
        }

        public V get(K key)
        {
            throw new NotImplementedException();
        }

        public V put(K key, V value)
        {
            throw new NotImplementedException();
        }

        public Set<MapEntry<K, V>> entrySet()
        {
            throw new NotImplementedException();
        }

        public bool containsKey(K key)
        {
            throw new NotImplementedException();
        }

        public Set<K> keySet()
        {
            throw new NotImplementedException();
        }

        public V putIfAbsent(K key, V value)
        {
            throw new NotImplementedException();
        }

        public V remove(K key)
        {
            throw new NotImplementedException();
        }

        public int size()
        {
            throw new NotImplementedException();
        }

        public bool isEmpty()
        {
            throw new NotImplementedException();
        }
    }

    class TreeMap : Map
    {
        public object get(object key)
        {
            throw new NotImplementedException();
        }

        public object put(object key, object value)
        {
            throw new NotImplementedException();
        }

        public Set entrySet()
        {
            throw new NotImplementedException();
        }

        public bool containsKey(object key)
        {
            throw new NotImplementedException();
        }

        public Set keySet()
        {
            throw new NotImplementedException();
        }

        public object putIfAbsent(object key, object value)
        {
            throw new NotImplementedException();
        }

        public object remove(object key)
        {
            throw new NotImplementedException();
        }

        public int size()
        {
            throw new NotImplementedException();
        }
    }
}
