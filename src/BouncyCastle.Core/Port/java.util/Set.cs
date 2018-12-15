namespace org.bouncycastle.Port.java.util
{
    public interface Set<T> : Collection<T>
    {
        bool contains(T value);
        bool containsAll(Set<string> otherActions);
    }

    public interface Set: Collection
    {
        void retainAll(Set otherNames);

        bool contains(object value);
    }
}
