namespace org.bouncycastle.Port.java.util
{
    public interface List<T>: Collection<T>
    {
        T get(int index);

        int indexOf(T o);

        int lastIndexOf(T o);

        T remove(int index);

        T set(int index, T element);
    }

    public interface List : Collection
    {
        object get(int index);

        int indexOf(object o);

        int lastIndexOf(object o);

        object remove(int index);

        object set(int index, object element);
    }
}
