using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.util
{

	/// <summary>
	/// A generic interface describing a simple store of objects.
	/// </summary>
	/// @param <T> the object type stored. </param>
	public interface Store<T>
	{
		/// <summary>
		/// Return a possibly empty collection of objects that match the criteria implemented
		/// in the passed in Selector.
		/// </summary>
		/// <param name="selector"> the selector defining the match criteria. </param>
		/// <returns> a collection of matching objects, empty if none available. </returns>
		/// <exception cref="StoreException"> if there is a failure during matching. </exception>
		Collection<T> getMatches(Selector<T> selector);
	}

}