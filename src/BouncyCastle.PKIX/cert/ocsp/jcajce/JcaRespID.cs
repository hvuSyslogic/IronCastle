namespace org.bouncycastle.cert.ocsp.jcajce
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	public class JcaRespID : RespID
	{
		public JcaRespID(X500Principal name) : base(X500Name.getInstance(name.getEncoded()))
		{
		}

		public JcaRespID(PublicKey pubKey, DigestCalculator digCalc) : base(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()), digCalc)
		{
		}
	}

}