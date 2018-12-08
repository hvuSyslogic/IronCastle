using System.Collections.Concurrent;

namespace org.bouncycastle.Port.java.util.concurrent
{
    public class ConcurrentHashMap<K, V> : ConcurrentMap<K, V>
    {
        private ConcurrentDictionary<K, V> _innerDictionary;

        public ConcurrentHashMap()
        {
            _innerDictionary = new ConcurrentDictionary<K, V>();
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

        public V get(K key)
        {
            if (_innerDictionary.ContainsKey(key))
                return _innerDictionary[key];

            return default(V);
        }
    }
}
