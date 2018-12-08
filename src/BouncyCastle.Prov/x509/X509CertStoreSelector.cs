namespace org.bouncycastle.x509
{

	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// This class is a Selector implementation for X.509 certificates.
	/// </summary>
	/// <seealso cref= org.bouncycastle.util.Selector </seealso>
	/// <seealso cref= org.bouncycastle.x509.X509Store </seealso>
	/// <seealso cref= org.bouncycastle.jce.provider.X509StoreCertCollection </seealso>
	/// @deprecated use the classes under org.bouncycastle.cert.selector 
	public class X509CertStoreSelector : X509CertSelector, Selector
	{
		public virtual bool match(object obj)
		{
			if (!(obj is X509Certificate))
			{
				return false;
			}

			X509Certificate other = (X509Certificate)obj;

			return base.match(other);
		}

		public virtual bool match(Certificate cert)
		{
			return match((object)cert);
		}

		public virtual object clone()
		{
			X509CertStoreSelector selector = (X509CertStoreSelector)base.clone();

			return selector;
		}

		/// <summary>
		/// Returns an instance of this from a <code>X509CertSelector</code>.
		/// </summary>
		/// <param name="selector"> A <code>X509CertSelector</code> instance. </param>
		/// <returns> An instance of an <code>X509CertStoreSelector</code>. </returns>
		/// <exception cref="IllegalArgumentException"> if selector is null or creation fails. </exception>
		public static X509CertStoreSelector getInstance(X509CertSelector selector)
		{
			if (selector == null)
			{
				throw new IllegalArgumentException("cannot create from null selector");
			}
			X509CertStoreSelector cs = new X509CertStoreSelector();
			cs.setAuthorityKeyIdentifier(selector.getAuthorityKeyIdentifier());
			cs.setBasicConstraints(selector.getBasicConstraints());
			cs.setCertificate(selector.getCertificate());
			cs.setCertificateValid(selector.getCertificateValid());
			cs.setMatchAllSubjectAltNames(selector.getMatchAllSubjectAltNames());
			try
			{
				cs.setPathToNames(selector.getPathToNames());
				cs.setExtendedKeyUsage(selector.getExtendedKeyUsage());
				cs.setNameConstraints(selector.getNameConstraints());
				cs.setPolicy(selector.getPolicy());
				cs.setSubjectPublicKeyAlgID(selector.getSubjectPublicKeyAlgID());
				cs.setSubjectAlternativeNames(selector.getSubjectAlternativeNames());
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("error in passed in selector: " + e);
			}
			cs.setIssuer(selector.getIssuer());
			cs.setKeyUsage(selector.getKeyUsage());
			cs.setPrivateKeyValid(selector.getPrivateKeyValid());
			cs.setSerialNumber(selector.getSerialNumber());
			cs.setSubject(selector.getSubject());
			cs.setSubjectKeyIdentifier(selector.getSubjectKeyIdentifier());
			cs.setSubjectPublicKey(selector.getSubjectPublicKey());
			return cs;
		}

	}

}