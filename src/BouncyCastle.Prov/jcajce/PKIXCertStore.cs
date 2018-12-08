namespace org.bouncycastle.jcajce
{

	using Selector = org.bouncycastle.util.Selector;
	using Store = org.bouncycastle.util.Store;
	using StoreException = org.bouncycastle.util.StoreException;

	/// <summary>
	/// Generic interface for a PKIX based certificate store.
	/// </summary>
	/// @param <T> the certificate type. </param>
	public interface PKIXCertStore<T> : Store<T> where T : java.security.cert.Certificate
	{
		/// <summary>
		/// Return the matches associated with the passed in selector.
		/// </summary>
		/// <param name="selector"> the selector defining the match criteria. </param>
		/// <returns> a collection of matches with the selector, an empty selector if there are none. </returns>
		/// <exception cref="StoreException"> in the event of an issue doing a match. </exception>
		Collection<T> getMatches(Selector<T> selector);
	}

}