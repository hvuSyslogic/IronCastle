namespace org.bouncycastle.jcajce.provider.util
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	public interface AsymmetricKeyInfoConverter
	{
		PrivateKey generatePrivate(PrivateKeyInfo keyInfo);

		PublicKey generatePublic(SubjectPublicKeyInfo keyInfo);
	}

}