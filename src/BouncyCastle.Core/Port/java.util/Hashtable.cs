using System;
using System.Collections.Concurrent;

namespace org.bouncycastle.Port.java.util
{
    public class Hashtable : Map
    {
        private ConcurrentDictionary<object, object> _innerDictionary;

        public Hashtable()
        {
            _innerDictionary = new ConcurrentDictionary<object, object>();
        }

        public Hashtable(int capacity)
        {
            _innerDictionary = new ConcurrentDictionary<object, object>();
        }

        public object get(object key)
        {
            return _innerDictionary[key];
        }

        public object put(object key, object value)
        {
            object prevValue = _innerDictionary[key];
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
            object prevValue = _innerDictionary[key];

            if (!_innerDictionary.ContainsKey(key))
                _innerDictionary[key] = value;

            return prevValue;
        }

        public object remove(object key)
        {
            object prevValue;
            _innerDictionary.TryRemove(key, out prevValue);

            return prevValue;
        }

        public int size()
        {
            return _innerDictionary.Count;
        }

        public Enumeration elements()
        {
            throw new NotImplementedException();
        }

        public Enumeration keys()
        {
            throw new NotImplementedException();
        }

        public bool isEmpty()
        {
            throw new NotImplementedException();
        }
    }

    public class Hashtable<K, V> : Map<K, V>
    {
        private ConcurrentDictionary<K, V> _innerDictionary;

        public Hashtable()
        {
            _innerDictionary = new ConcurrentDictionary<K, V>();
        }

        public Hashtable(int capacity)
        {
            _innerDictionary = new ConcurrentDictionary<K, V>();
        }

        public V get(K key)
        {
            return _innerDictionary[key];
        }

        public V put(K key, V value)
        {
            V prevValue = _innerDictionary[key];
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
            V prevValue = _innerDictionary[key];

            if (!_innerDictionary.ContainsKey(key))
                _innerDictionary[key] = value;

            return prevValue;
        }

        public V remove(K key)
        {
            V prevValue;
            _innerDictionary.TryRemove(key, out prevValue);

            return prevValue;
        }

        public int size()
        {
            return _innerDictionary.Count;
        }

        public bool isEmpty()
        {
            throw new NotImplementedException();
        }

        public Enumeration<V> elements()
        {
            throw new NotImplementedException();
        }

        public Enumeration<K> keys()
        {
            throw new NotImplementedException();
        }
    }
}
