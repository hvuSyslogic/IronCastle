namespace org.bouncycastle.cert.jcajce
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	public class JcaAttributeCertificateIssuer : AttributeCertificateIssuer
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="issuerCert"> certificate for the issuer of the attribute certificate. </param>
		public JcaAttributeCertificateIssuer(X509Certificate issuerCert) : this(issuerCert.getIssuerX500Principal())
		{
		}

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="issuerDN"> X.500 DN for the issuer of the attribute certificate. </param>
		public JcaAttributeCertificateIssuer(X500Principal issuerDN) : base(X500Name.getInstance(issuerDN.getEncoded()))
		{
		}
	}

}