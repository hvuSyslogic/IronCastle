namespace org.bouncycastle.cert.crmf.jcajce
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	public class JcaPKIArchiveControlBuilder : PKIArchiveControlBuilder
	{
		public JcaPKIArchiveControlBuilder(PrivateKey privateKey, X500Name name) : this(privateKey, new GeneralName(name))
		{
		}

		public JcaPKIArchiveControlBuilder(PrivateKey privateKey, X500Principal name) : this(privateKey, X500Name.getInstance(name.getEncoded()))
		{
		}

		public JcaPKIArchiveControlBuilder(PrivateKey privateKey, GeneralName generalName) : base(PrivateKeyInfo.getInstance(privateKey.getEncoded()), generalName)
		{
		}
	}

}