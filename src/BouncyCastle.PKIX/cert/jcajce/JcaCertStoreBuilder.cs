namespace org.bouncycastle.cert.jcajce
{

	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// Builder to create a CertStore from certificate and CRL stores.
	/// </summary>
	public class JcaCertStoreBuilder
	{
		private List certs = new ArrayList();
		private List crls = new ArrayList();
		private object provider;
		private JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
		private JcaX509CRLConverter crlConverter = new JcaX509CRLConverter();
		private string type = "Collection";

		/// <summary>
		///  Add a store full of X509CertificateHolder objects.
		/// </summary>
		/// <param name="certStore"> a store of X509CertificateHolder objects. </param>
		public virtual JcaCertStoreBuilder addCertificates(Store certStore)
		{
			certs.addAll(certStore.getMatches(null));

			return this;
		}

		/// <summary>
		/// Add a single certificate.
		/// </summary>
		/// <param name="cert">  the X509 certificate holder containing the certificate. </param>
		public virtual JcaCertStoreBuilder addCertificate(X509CertificateHolder cert)
		{
			certs.add(cert);

			return this;
		}

		/// <summary>
		/// Add a store full of X509CRLHolder objects. </summary>
		/// <param name="crlStore">  a store of X509CRLHolder objects. </param>
		public virtual JcaCertStoreBuilder addCRLs(Store crlStore)
		{
			crls.addAll(crlStore.getMatches(null));

			return this;
		}

		/// <summary>
		/// Add a single CRL.
		/// </summary>
		/// <param name="crl">  the X509 CRL holder containing the CRL. </param>
		public virtual JcaCertStoreBuilder addCRL(X509CRLHolder crl)
		{
			crls.add(crl);

			return this;
		}

		public virtual JcaCertStoreBuilder setProvider(string providerName)
		{
			certificateConverter.setProvider(providerName);
			crlConverter.setProvider(providerName);
			this.provider = providerName;

			return this;
		}

		public virtual JcaCertStoreBuilder setProvider(Provider provider)
		{
			certificateConverter.setProvider(provider);
			crlConverter.setProvider(provider);
			this.provider = provider;

			return this;
		}

		/// <summary>
		/// Set the type of the CertStore generated. By default it is "Collection".
		/// </summary>
		/// <param name="type"> type of CertStore passed to CertStore.getInstance(). </param>
		/// <returns> the current builder. </returns>
		public virtual JcaCertStoreBuilder setType(string type)
		{
			this.type = type;

			return this;
		}

		/// <summary>
		/// Build the CertStore from the current inputs.
		/// </summary>
		/// <returns>  a CertStore. </returns>
		/// <exception cref="GeneralSecurityException"> </exception>
		public virtual CertStore build()
		{
			CollectionCertStoreParameters @params = convertHolders(certificateConverter, crlConverter);

			if (provider is string)
			{
				return CertStore.getInstance(type, @params, (string)provider);
			}

			if (provider is Provider)
			{
				return CertStore.getInstance(type, @params, (Provider)provider);
			}

			return CertStore.getInstance(type, @params);
		}

		private CollectionCertStoreParameters convertHolders(JcaX509CertificateConverter certificateConverter, JcaX509CRLConverter crlConverter)
		{
			List jcaObjs = new ArrayList(certs.size() + crls.size());

			for (Iterator it = certs.iterator(); it.hasNext();)
			{
				jcaObjs.add(certificateConverter.getCertificate((X509CertificateHolder)it.next()));
			}

			for (Iterator it = crls.iterator(); it.hasNext();)
			{
				jcaObjs.add(crlConverter.getCRL((X509CRLHolder)it.next()));
			}

			return new CollectionCertStoreParameters(jcaObjs);
		}
	}

}