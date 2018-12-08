namespace org.bouncycastle.jce.provider
{

	using Selector = org.bouncycastle.util.Selector;
	using StoreException = org.bouncycastle.util.StoreException;
	using X509CRLStoreSelector = org.bouncycastle.x509.X509CRLStoreSelector;
	using X509StoreParameters = org.bouncycastle.x509.X509StoreParameters;
	using X509StoreSpi = org.bouncycastle.x509.X509StoreSpi;
	using LDAPStoreHelper = org.bouncycastle.x509.util.LDAPStoreHelper;

	/// <summary>
	/// A SPI implementation of Bouncy Castle <code>X509Store</code> for getting
	/// certificate revocation lists from an LDAP directory.
	/// </summary>
	/// <seealso cref= org.bouncycastle.x509.X509Store </seealso>
	public class X509StoreLDAPCRLs : X509StoreSpi
	{

		private LDAPStoreHelper helper;

		public X509StoreLDAPCRLs()
		{
		}

		/// <summary>
		/// Initializes this LDAP CRL store implementation.
		/// </summary>
		/// <param name="params"> <code>X509LDAPCertStoreParameters</code>. </param>
		/// <exception cref="IllegalArgumentException"> if <code>params</code> is not an instance of
		///                                  <code>X509LDAPCertStoreParameters</code>. </exception>
		public override void engineInit(X509StoreParameters @params)
		{
			if (!(@params is X509LDAPCertStoreParameters))
			{
				throw new IllegalArgumentException("Initialization parameters must be an instance of " + typeof(X509LDAPCertStoreParameters).getName() + ".");
			}
			helper = new LDAPStoreHelper((X509LDAPCertStoreParameters)@params);
		}

		/// <summary>
		/// Returns a collection of matching CRLs from the LDAP location.
		/// <para>
		/// The selector must be a of type <code>X509CRLStoreSelector</code>. If
		/// it is not an empty collection is returned.
		/// </para>
		/// </para><para>
		/// The issuer should be a reasonable criteria for a selector.
		/// </p> </summary>
		/// <param name="selector"> The selector to use for finding. </param>
		/// <returns> A collection with the matches. </returns>
		/// <exception cref="StoreException"> if an exception occurs while searching. </exception>
		public override Collection engineGetMatches(Selector selector)
		{
			if (!(selector is X509CRLStoreSelector))
			{
				return Collections.EMPTY_SET;
			}
			X509CRLStoreSelector xselector = (X509CRLStoreSelector)selector;
			Set set = new HashSet();
			// test only delta CRLs should be selected
			if (xselector.isDeltaCRLIndicatorEnabled())
			{
				set.addAll(helper.getDeltaCertificateRevocationLists(xselector));
			}
			// nothing specified
			else
			{
				set.addAll(helper.getDeltaCertificateRevocationLists(xselector));
				set.addAll(helper.getAttributeAuthorityRevocationLists(xselector));
				set.addAll(helper.getAttributeCertificateRevocationLists(xselector));
				set.addAll(helper.getAuthorityRevocationLists(xselector));
				set.addAll(helper.getCertificateRevocationLists(xselector));
			}
			return set;
		}
	}

}