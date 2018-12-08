namespace org.bouncycastle.jcajce
{

	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// This class is a Selector implementation for certificates.
	/// </summary>
	/// <seealso cref= org.bouncycastle.util.Selector </seealso>
	public class PKIXCertStoreSelector<T> : Selector<T> where T : java.security.cert.Certificate
	{
		/// <summary>
		/// Builder for a PKIXCertStoreSelector.
		/// </summary>
		public class Builder
		{
			internal readonly CertSelector baseSelector;

			/// <summary>
			/// Constructor initializing a builder with a CertSelector.
			/// </summary>
			/// <param name="certSelector"> the CertSelector to copy the match details from. </param>
			public Builder(CertSelector certSelector)
			{
				this.baseSelector = (CertSelector)certSelector.clone();
			}

			/// <summary>
			/// Build a selector.
			/// </summary>
			/// <returns> a new PKIXCertStoreSelector </returns>
//JAVA TO C# CONVERTER WARNING: Java wildcard generics have no direct equivalent in .NET:
//ORIGINAL LINE: public PKIXCertStoreSelector<? extends java.security.cert.Certificate> build()
			public virtual PKIXCertStoreSelector<Certificate> build()
			{
				return new PKIXCertStoreSelector(baseSelector);
			}
		}

		private readonly CertSelector baseSelector;

		private PKIXCertStoreSelector(CertSelector baseSelector)
		{
			this.baseSelector = baseSelector;
		}

		public virtual bool match(Certificate cert)
		{
			return baseSelector.match(cert);
		}

		public virtual object clone()
		{
			return new PKIXCertStoreSelector(baseSelector);
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public static java.util.Collection<? extends java.security.cert.Certificate> getCertificates(final PKIXCertStoreSelector selector, java.security.cert.CertStore certStore) throws java.security.cert.CertStoreException
//JAVA TO C# CONVERTER WARNING: Java wildcard generics have no direct equivalent in .NET:
		public static Collection<Certificate> getCertificates(PKIXCertStoreSelector selector, CertStore certStore)
		{
			return certStore.getCertificates(new SelectorClone(selector));
		}

		public class SelectorClone : X509CertSelector
		{
			internal readonly PKIXCertStoreSelector selector;

			public SelectorClone(PKIXCertStoreSelector selector)
			{
				this.selector = selector;

				if (selector.baseSelector is X509CertSelector)
				{
					X509CertSelector baseSelector = (X509CertSelector)selector.baseSelector;

					this.setAuthorityKeyIdentifier(baseSelector.getAuthorityKeyIdentifier());
					this.setBasicConstraints(baseSelector.getBasicConstraints());
					this.setCertificate(baseSelector.getCertificate());
					this.setCertificateValid(baseSelector.getCertificateValid());
					this.setKeyUsage(baseSelector.getKeyUsage());
					this.setMatchAllSubjectAltNames(baseSelector.getMatchAllSubjectAltNames());
					this.setPrivateKeyValid(baseSelector.getPrivateKeyValid());
					this.setSerialNumber(baseSelector.getSerialNumber());
					this.setSubjectKeyIdentifier(baseSelector.getSubjectKeyIdentifier());
					this.setSubjectPublicKey(baseSelector.getSubjectPublicKey());

					try
					{
						this.setExtendedKeyUsage(baseSelector.getExtendedKeyUsage());
						this.setIssuer(baseSelector.getIssuerAsBytes());
						this.setNameConstraints(baseSelector.getNameConstraints());
						this.setPathToNames(baseSelector.getPathToNames());
						this.setPolicy(baseSelector.getPolicy());
						this.setSubject(baseSelector.getSubjectAsBytes());
						this.setSubjectAlternativeNames(baseSelector.getSubjectAlternativeNames());
						this.setSubjectPublicKeyAlgID(baseSelector.getSubjectPublicKeyAlgID());
					}
					catch (IOException e)
					{
						throw new IllegalStateException("base selector invalid: " + e.Message, e);
					}
				}
			}

			public virtual bool match(Certificate certificate)
			{
				return (selector == null) ? (certificate != null) : selector.match(certificate);
			}
		}
	}

}