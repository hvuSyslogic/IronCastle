namespace org.bouncycastle.cert.ocsp.jcajce
{

	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	public class JcaCertificateID : CertificateID
	{
		public JcaCertificateID(DigestCalculator digestCalculator, X509Certificate issuerCert, BigInteger number) : base(digestCalculator, new JcaX509CertificateHolder(issuerCert), number)
		{
		}
	}

}