namespace org.bouncycastle.openssl
{
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	public class PEMKeyPair
	{
		private readonly SubjectPublicKeyInfo publicKeyInfo;
		private readonly PrivateKeyInfo privateKeyInfo;

		public PEMKeyPair(SubjectPublicKeyInfo publicKeyInfo, PrivateKeyInfo privateKeyInfo)
		{
			this.publicKeyInfo = publicKeyInfo;
			this.privateKeyInfo = privateKeyInfo;
		}

		public virtual PrivateKeyInfo getPrivateKeyInfo()
		{
			return privateKeyInfo;
		}

		public virtual SubjectPublicKeyInfo getPublicKeyInfo()
		{
			return publicKeyInfo;
		}
	}

}