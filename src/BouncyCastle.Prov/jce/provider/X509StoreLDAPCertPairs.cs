namespace org.bouncycastle.jce.provider
{

	using Selector = org.bouncycastle.util.Selector;
	using StoreException = org.bouncycastle.util.StoreException;
	using X509CertPairStoreSelector = org.bouncycastle.x509.X509CertPairStoreSelector;
	using X509StoreParameters = org.bouncycastle.x509.X509StoreParameters;
	using X509StoreSpi = org.bouncycastle.x509.X509StoreSpi;
	using LDAPStoreHelper = org.bouncycastle.x509.util.LDAPStoreHelper;

	/// <summary>
	/// A SPI implementation of Bouncy Castle <code>X509Store</code> for getting
	/// cross certificates pairs from an LDAP directory.
	/// </summary>
	/// <seealso cref= org.bouncycastle.x509.X509Store </seealso>
	public class X509StoreLDAPCertPairs : X509StoreSpi
	{

		private LDAPStoreHelper helper;

		public X509StoreLDAPCertPairs()
		{
		}

		/// <summary>
		/// Initializes this LDAP cross certificate pair store implementation.
		/// </summary>
		/// <param name="parameters"> <code>X509LDAPCertStoreParameters</code>. </param>
		/// <exception cref="IllegalArgumentException"> if <code>params</code> is not an instance of
		///                                  <code>X509LDAPCertStoreParameters</code>. </exception>
		public override void engineInit(X509StoreParameters parameters)
		{
			if (!(parameters is X509LDAPCertStoreParameters))
			{
				throw new IllegalArgumentException("Initialization parameters must be an instance of " + typeof(X509LDAPCertStoreParameters).getName() + ".");
			}
			helper = new LDAPStoreHelper((X509LDAPCertStoreParameters)parameters);
		}

		/// <summary>
		/// Returns a collection of matching cross certificate pairs from the LDAP
		/// location.
		/// <para>
		/// The selector must be a of type <code>X509CertPairStoreSelector</code>.
		/// If it is not an empty collection is returned.
		/// </para>
		/// <para>
		/// The subject should be a reasonable criteria for a selector.
		/// </para> </summary>
		/// <param name="selector"> The selector to use for finding. </param>
		/// <returns> A collection with the matches. </returns>
		/// <exception cref="StoreException"> if an exception occurs while searching. </exception>
		public override Collection engineGetMatches(Selector selector)
		{
			if (!(selector is X509CertPairStoreSelector))
			{
				return Collections.EMPTY_SET;
			}
			X509CertPairStoreSelector xselector = (X509CertPairStoreSelector)selector;
			Set set = new HashSet();
			set.addAll(helper.getCrossCertificatePairs(xselector));
			return set;
		}

	}

}