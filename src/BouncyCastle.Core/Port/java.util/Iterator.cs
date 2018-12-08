namespace org.bouncycastle.Port.java.util
{
    public interface Iterator<T>
    {
        bool hasNext();

        T next();
    }

    public interface Iterator
    {
        bool hasNext();

        object next();
    }
}
