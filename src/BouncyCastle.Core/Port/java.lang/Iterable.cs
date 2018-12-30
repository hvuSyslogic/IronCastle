using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.Port.java.lang
{
    public interface Iterable<T> 
    {
        /// <summary>
        /// Returns an iterator over a set of elements of type T.
        /// </summary>
        /// <returns> an Iterator. </returns>
        Iterator<T> iterator();
    }

    public interface Iterable
    {
        /// <summary>
        /// Returns an iterator over a set of elements of type T.
        /// </summary>
        /// <returns> an Iterator. </returns>
        Iterator iterator();
    }
}
