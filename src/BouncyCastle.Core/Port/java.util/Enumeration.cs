namespace org.bouncycastle.Port.java.util
{
    public interface Enumeration<T>
    {
        bool hasMoreElements();

        T nextElement();
    }

    public interface Enumeration
    {
        bool hasMoreElements();

        object nextElement();
    }
}
