namespace org.bouncycastle.jce.provider
{

	using CollectionStore = org.bouncycastle.util.CollectionStore;
	using Selector = org.bouncycastle.util.Selector;
	using X509CollectionStoreParameters = org.bouncycastle.x509.X509CollectionStoreParameters;
	using X509StoreParameters = org.bouncycastle.x509.X509StoreParameters;
	using X509StoreSpi = org.bouncycastle.x509.X509StoreSpi;

	/// <summary>
	/// This class is a collection based Bouncy Castle
	/// <seealso cref="org.bouncycastle.x509.X509Store"/> SPI implementation for certificate
	/// pairs.
	/// </summary>
	/// <seealso cref= org.bouncycastle.x509.X509Store </seealso>
	/// <seealso cref= org.bouncycastle.x509.X509CertificatePair </seealso>
	public class X509StoreCertPairCollection : X509StoreSpi
	{

		private CollectionStore _store;

		public X509StoreCertPairCollection()
		{
		}

		/// <summary>
		/// Initializes this store.
		/// </summary>
		/// <param name="params"> The <seealso cref="X509CollectionStoreParameters"/>s for this store. </param>
		/// <exception cref="IllegalArgumentException"> if <code>params</code> is no instance of
		///                                  <code>X509CollectionStoreParameters</code>. </exception>
		public override void engineInit(X509StoreParameters @params)
		{
			if (!(@params is X509CollectionStoreParameters))
			{
				throw new IllegalArgumentException("Initialization parameters must be an instance of " + typeof(X509CollectionStoreParameters).getName() + ".");
			}

			_store = new CollectionStore(((X509CollectionStoreParameters)@params).getCollection());
		}

		/// <summary>
		/// Returns a colelction of certificate pairs which match the given
		/// <code>selector</code>.
		/// <para>
		/// The returned collection contains
		/// <seealso cref="org.bouncycastle.x509.X509CertificatePair"/>s. The selector must be
		/// a <seealso cref="org.bouncycastle.x509.X509CertPairStoreSelector"/> to select
		/// certificate pairs.
		/// </para> </summary>
		/// <returns> A collection with matching certificate pairs. </returns>
		public override Collection engineGetMatches(Selector selector)
		{
			return _store.getMatches(selector);
		}
	}

}