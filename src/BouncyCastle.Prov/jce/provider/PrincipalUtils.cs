namespace org.bouncycastle.jce.provider
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X509AttributeCertificate = org.bouncycastle.x509.X509AttributeCertificate;

	public class PrincipalUtils
	{
		internal static X500Name getSubjectPrincipal(X509Certificate cert)
		{
			return X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
		}

		internal static X500Name getIssuerPrincipal(X509CRL crl)
		{
			return X500Name.getInstance(crl.getIssuerX500Principal().getEncoded());
		}

		internal static X500Name getIssuerPrincipal(X509Certificate cert)
		{
			return X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
		}

		internal static X500Name getCA(TrustAnchor trustAnchor)
		{
			return X500Name.getInstance(trustAnchor.getCA().getEncoded());
		}

		/// <summary>
		/// Returns the issuer of an attribute certificate or certificate.
		/// </summary>
		/// <param name="cert"> The attribute certificate or certificate. </param>
		/// <returns> The issuer as <code>X500Principal</code>. </returns>
		internal static X500Name getEncodedIssuerPrincipal(object cert)
		{
			if (cert is X509Certificate)
			{
				return getIssuerPrincipal((X509Certificate)cert);
			}
			else
			{
				return X500Name.getInstance(((X500Principal)((X509AttributeCertificate)cert).getIssuer().getPrincipals()[0]).getEncoded());
			}
		}
	}

}