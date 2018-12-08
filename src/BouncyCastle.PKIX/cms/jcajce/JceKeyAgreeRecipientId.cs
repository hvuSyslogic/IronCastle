namespace org.bouncycastle.cms.jcajce
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	public class JceKeyAgreeRecipientId : KeyAgreeRecipientId
	{
		public JceKeyAgreeRecipientId(X509Certificate certificate) : this(certificate.getIssuerX500Principal(), certificate.getSerialNumber())
		{
		}

		public JceKeyAgreeRecipientId(X500Principal issuer, BigInteger serialNumber) : base(X500Name.getInstance(issuer.getEncoded()), serialNumber)
		{
		}
	}

}