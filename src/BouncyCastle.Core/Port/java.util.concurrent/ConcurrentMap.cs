namespace org.bouncycastle.Port.java.util.concurrent
{
    public interface ConcurrentMap<K, V>
    {
        V putIfAbsent(K key, V value);

        V get(K key);
    }
}
