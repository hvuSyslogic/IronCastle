namespace org.bouncycastle.pkcs.jcajce
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	public class JcaPKCS12SafeBagBuilder : PKCS12SafeBagBuilder
	{
		public JcaPKCS12SafeBagBuilder(X509Certificate certificate) : base(convertCert(certificate))
		{
		}

		private static Certificate convertCert(X509Certificate certificate)
		{
			try
			{
				return Certificate.getInstance(certificate.getEncoded());
			}
			catch (CertificateEncodingException e)
			{
				throw new PKCSIOException("cannot encode certificate: " + e.Message, e);
			}
		}

		public JcaPKCS12SafeBagBuilder(PrivateKey privateKey, OutputEncryptor encryptor) : base(PrivateKeyInfo.getInstance(privateKey.getEncoded()), encryptor)
		{
		}

		public JcaPKCS12SafeBagBuilder(PrivateKey privateKey) : base(PrivateKeyInfo.getInstance(privateKey.getEncoded()))
		{
		}
	}

}