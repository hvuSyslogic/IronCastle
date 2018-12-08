namespace org.bouncycastle.jce.provider
{

	using Selector = org.bouncycastle.util.Selector;
	using StoreException = org.bouncycastle.util.StoreException;
	using X509CertPairStoreSelector = org.bouncycastle.x509.X509CertPairStoreSelector;
	using X509CertStoreSelector = org.bouncycastle.x509.X509CertStoreSelector;
	using X509CertificatePair = org.bouncycastle.x509.X509CertificatePair;
	using X509StoreParameters = org.bouncycastle.x509.X509StoreParameters;
	using X509StoreSpi = org.bouncycastle.x509.X509StoreSpi;
	using LDAPStoreHelper = org.bouncycastle.x509.util.LDAPStoreHelper;

	/// <summary>
	/// A SPI implementation of Bouncy Castle <code>X509Store</code> for getting
	/// certificates form a LDAP directory.
	/// </summary>
	/// <seealso cref= org.bouncycastle.x509.X509Store </seealso>
	public class X509StoreLDAPCerts : X509StoreSpi
	{

		private LDAPStoreHelper helper;

		public X509StoreLDAPCerts()
		{
		}

		/// <summary>
		/// Initializes this LDAP cert store implementation.
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
		/// Returns a collection of matching certificates from the LDAP location.
		/// <para>
		/// The selector must be a of type <code>X509CertStoreSelector</code>. If
		/// it is not an empty collection is returned.
		/// </para>
		/// </para><para>
		/// The implementation searches only for CA certificates, if the method
		/// <seealso cref="java.security.cert.X509CertSelector#getBasicConstraints()"/> is
		/// greater or equal to 0. If it is -2 only end certificates are searched.
		/// </para><para>
		/// The subject and the serial number for end certificates should be
		/// reasonable criterias for a selector.
		/// </p> </summary>
		/// <param name="selector"> The selector to use for finding. </param>
		/// <returns> A collection with the matches. </returns>
		/// <exception cref="StoreException"> if an exception occurs while searching. </exception>
		public override Collection engineGetMatches(Selector selector)
		{
			if (!(selector is X509CertStoreSelector))
			{
				return Collections.EMPTY_SET;
			}
			X509CertStoreSelector xselector = (X509CertStoreSelector)selector;
			Set set = new HashSet();
			// test if only CA certificates should be selected
			if (xselector.getBasicConstraints() > 0)
			{
				set.addAll(helper.getCACertificates(xselector));
				set.addAll(getCertificatesFromCrossCertificatePairs(xselector));
			}
			// only end certificates should be selected
			else if (xselector.getBasicConstraints() == -2)
			{
				set.addAll(helper.getUserCertificates(xselector));
			}
			// nothing specified
			else
			{
				set.addAll(helper.getUserCertificates(xselector));
				set.addAll(helper.getCACertificates(xselector));
				set.addAll(getCertificatesFromCrossCertificatePairs(xselector));
			}
			return set;
		}

		private Collection getCertificatesFromCrossCertificatePairs(X509CertStoreSelector xselector)
		{
			Set set = new HashSet();
			X509CertPairStoreSelector ps = new X509CertPairStoreSelector();

			ps.setForwardSelector(xselector);
			ps.setReverseSelector(new X509CertStoreSelector());

			Set crossCerts = new HashSet(helper.getCrossCertificatePairs(ps));
			Set forward = new HashSet();
			Set reverse = new HashSet();
			Iterator it = crossCerts.iterator();
			while (it.hasNext())
			{
				X509CertificatePair pair = (X509CertificatePair)it.next();
				if (pair.getForward() != null)
				{
					forward.add(pair.getForward());
				}
				if (pair.getReverse() != null)
				{
					reverse.add(pair.getReverse());
				}
			}
			set.addAll(forward);
			set.addAll(reverse);
			return set;
		}
	}

}