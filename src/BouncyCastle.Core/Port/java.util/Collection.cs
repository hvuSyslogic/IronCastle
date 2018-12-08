using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.Port.java.util
{
    public interface Collection<T> : Iterable<T>
    {
        bool add(T e);

        bool addAll(Collection<T> c);

        int size();

        bool isEmpty();

        T[] toArray();
    }

    public interface Collection : Iterable
    {
        bool add(object e);

        bool addAll(Collection c);

        int size();

        bool isEmpty();

        object[] toArray();
    }
}
