using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.util
{

	/// <summary>
	/// Utility class to allow use of Iterable feature in JDK 1.5+
	/// </summary>
	public interface Iterable<T> : org.bouncycastle.Port.java.lang.Iterable<T>
	{
		/// <summary>
		/// Returns an iterator over a set of elements of type T.
		/// </summary>
		/// <returns> an Iterator. </returns>
		Iterator<T> iterator();
	}

}