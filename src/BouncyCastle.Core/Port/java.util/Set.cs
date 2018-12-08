namespace org.bouncycastle.Port.java.util
{
    public interface Set<T> : Collection<T>
    {
        bool contains(T value);
    }

    public interface Set: Collection
    {
        void retainAll(Set otherNames);

        bool contains(object value);
    }
}
