namespace org.bouncycastle.Port.java.util
{
    public interface Map<K,V>
    {
        V get(K key);
      
         V put(K key, V value);

        Set<MapEntry<K, V>> entrySet();

        bool containsKey(K key);

        Set<K> keySet();

        V putIfAbsent(K key, V value);

        V remove(K key);

        int size();
        bool isEmpty();
    }

    public interface Map
    {
        object get(object key);

        object put(object key, object value);

        Set entrySet();

        bool containsKey(object key);

        Set keySet();

        object putIfAbsent(object key, object value);

        object remove(object key);

        int size();
    }
}
