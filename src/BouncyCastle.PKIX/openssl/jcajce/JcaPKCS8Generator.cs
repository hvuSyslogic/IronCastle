namespace org.bouncycastle.openssl.jcajce
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using PemGenerationException = org.bouncycastle.util.io.pem.PemGenerationException;

	public class JcaPKCS8Generator : PKCS8Generator
	{
		public JcaPKCS8Generator(PrivateKey key, OutputEncryptor encryptor) : base(PrivateKeyInfo.getInstance(key.getEncoded()), encryptor)
		{
		}
	}

}