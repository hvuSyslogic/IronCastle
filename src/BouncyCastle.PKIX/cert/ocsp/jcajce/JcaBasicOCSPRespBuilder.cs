namespace org.bouncycastle.cert.ocsp.jcajce
{

	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	public class JcaBasicOCSPRespBuilder : BasicOCSPRespBuilder
	{
		public JcaBasicOCSPRespBuilder(PublicKey key, DigestCalculator digCalc) : base(SubjectPublicKeyInfo.getInstance(key.getEncoded()), digCalc)
		{
		}
	}

}