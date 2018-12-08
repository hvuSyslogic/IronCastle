using System;
using System.Collections.Generic;

namespace org.bouncycastle.Port.java.util
{
    public class HashMap : Map
    {
        private readonly Dictionary<object, object> _innerDictionary;

        public HashMap()
        {
            _innerDictionary = new Dictionary<object, object>();
        }

        public object get(object key)
        {
            if (_innerDictionary.ContainsKey(key))
                return _innerDictionary[key];

            return default(object);
        }

        public object put(object key, object value)
        {
            object prevValue = default(object);

            if (_innerDictionary.ContainsKey(key))
                prevValue = _innerDictionary[key];

            _innerDictionary[key] = value;

            return prevValue;
        }

        public Set entrySet()
        {
            throw new NotImplementedException();
        }

        public bool containsKey(object key)
        {
            return _innerDictionary.ContainsKey(key);
        }

        public Set keySet()
        {
            throw new NotImplementedException();
        }

        public object putIfAbsent(object key, object value)
        {
            object prevValue = default(object);

            if (_innerDictionary.ContainsKey(key))
                prevValue = _innerDictionary[key];
            else
                _innerDictionary[key] = value;

            return prevValue;
        }

        public object remove(object key)
        {
            object prevValue = default(object);

            if (_innerDictionary.ContainsKey(key))
                prevValue = _innerDictionary[key];

            _innerDictionary.Remove(key);

            return prevValue;
        }

        public int size()
        {
            return _innerDictionary.Count;
        }
    }


    public class HashMap<K, V> : Map<K, V>
    {
        private readonly Dictionary<K, V> _innerDictionary;

        public HashMap()
        {
            _innerDictionary = new Dictionary<K, V>();
        }

        public V get(K key)
        {
            if (_innerDictionary.ContainsKey(key))
                return _innerDictionary[key];

            return default(V);
        }

        public V put(K key, V value)
        {
            V prevValue = default(V);

            if (_innerDictionary.ContainsKey(key))
                prevValue = _innerDictionary[key];

            _innerDictionary[key] = value;

            return prevValue;
        }

        public Set<MapEntry<K, V>> entrySet()
        {
            throw new NotImplementedException();
        }

        public bool containsKey(K key)
        {
            return _innerDictionary.ContainsKey(key);
        }

        public Set<K> keySet()
        {
            throw new NotImplementedException();
        }

        public V putIfAbsent(K key, V value)
        {
            V prevValue = default(V);

            if (_innerDictionary.ContainsKey(key))
                prevValue = _innerDictionary[key];
            else
                _innerDictionary[key] = value;

            return prevValue;
        }

        public V remove(K key)
        {
            V prevValue = default(V);

            if (_innerDictionary.ContainsKey(key))
                prevValue = _innerDictionary[key];

            _innerDictionary.Remove(key);

            return prevValue;
        }

        public int size()
        {
            return _innerDictionary.Count;
        }
    }
}
