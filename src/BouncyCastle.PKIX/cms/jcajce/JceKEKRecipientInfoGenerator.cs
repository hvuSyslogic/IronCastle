namespace org.bouncycastle.cms.jcajce
{

	using KEKIdentifier = org.bouncycastle.asn1.cms.KEKIdentifier;
	using JceSymmetricKeyWrapper = org.bouncycastle.@operator.jcajce.JceSymmetricKeyWrapper;

	public class JceKEKRecipientInfoGenerator : KEKRecipientInfoGenerator
	{
		public JceKEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, SecretKey keyEncryptionKey) : base(kekIdentifier, new JceSymmetricKeyWrapper(keyEncryptionKey))
		{
		}

		public JceKEKRecipientInfoGenerator(byte[] keyIdentifier, SecretKey keyEncryptionKey) : this(new KEKIdentifier(keyIdentifier, null, null), keyEncryptionKey)
		{
		}

		public virtual JceKEKRecipientInfoGenerator setProvider(Provider provider)
		{
			((JceSymmetricKeyWrapper)this.wrapper).setProvider(provider);

			return this;
		}

		public virtual JceKEKRecipientInfoGenerator setProvider(string providerName)
		{
			((JceSymmetricKeyWrapper)this.wrapper).setProvider(providerName);

			return this;
		}

		public virtual JceKEKRecipientInfoGenerator setSecureRandom(SecureRandom random)
		{
			((JceSymmetricKeyWrapper)this.wrapper).setSecureRandom(random);

			return this;
		}
	}

}