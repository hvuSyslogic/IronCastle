namespace org.bouncycastle.Port.java.util
{
    public interface MapEntry<K, V>
    {
        K getKey();

        V getValue();

        V setValue(V value);
    }

    public interface MapEntry
    {
        string getKey();

        object getValue();

        object setValue(object value);
    }
}