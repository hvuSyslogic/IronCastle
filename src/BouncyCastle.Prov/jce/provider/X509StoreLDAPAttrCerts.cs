namespace org.bouncycastle.jce.provider
{

	using Selector = org.bouncycastle.util.Selector;
	using StoreException = org.bouncycastle.util.StoreException;
	using X509AttributeCertStoreSelector = org.bouncycastle.x509.X509AttributeCertStoreSelector;
	using X509StoreParameters = org.bouncycastle.x509.X509StoreParameters;
	using X509StoreSpi = org.bouncycastle.x509.X509StoreSpi;
	using LDAPStoreHelper = org.bouncycastle.x509.util.LDAPStoreHelper;

	/// <summary>
	/// A SPI implementation of Bouncy Castle <code>X509Store</code> for getting
	/// attribute certificates from an LDAP directory.
	/// </summary>
	/// <seealso cref= org.bouncycastle.x509.X509Store </seealso>
	public class X509StoreLDAPAttrCerts : X509StoreSpi
	{

		private LDAPStoreHelper helper;

		public X509StoreLDAPAttrCerts()
		{
		}

		/// <summary>
		/// Initializes this LDAP attribute cert store implementation.
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
		/// Returns a collection of matching attribute certificates from the LDAP
		/// location.
		/// <para>
		/// The selector must be a of type
		/// <code>X509AttributeCertStoreSelector</code>. If it is not an empty
		/// collection is returned.
		/// </para>
		/// <para>
		/// The subject and the serial number should be reasonable criterias for a
		/// selector.
		/// </para> </summary>
		/// <param name="selector"> The selector to use for finding. </param>
		/// <returns> A collection with the matches. </returns>
		/// <exception cref="StoreException"> if an exception occurs while searching. </exception>
		public override Collection engineGetMatches(Selector selector)
		{
			if (!(selector is X509AttributeCertStoreSelector))
			{
				return Collections.EMPTY_SET;
			}
			X509AttributeCertStoreSelector xselector = (X509AttributeCertStoreSelector)selector;
			Set set = new HashSet();
			set.addAll(helper.getAACertificates(xselector));
			set.addAll(helper.getAttributeCertificateAttributes(xselector));
			set.addAll(helper.getAttributeDescriptorCertificates(xselector));
			return set;
		}

	}

}