namespace org.bouncycastle.pkcs.jcajce
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

	public class JcaPKCS8EncryptedPrivateKeyInfoBuilder : PKCS8EncryptedPrivateKeyInfoBuilder
	{
		public JcaPKCS8EncryptedPrivateKeyInfoBuilder(PrivateKey privateKey) : base(PrivateKeyInfo.getInstance(privateKey.getEncoded()))
		{
		}
	}

}