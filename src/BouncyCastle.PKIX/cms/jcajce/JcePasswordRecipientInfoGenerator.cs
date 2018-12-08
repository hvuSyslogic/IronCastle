namespace org.bouncycastle.cms.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GenericKey = org.bouncycastle.@operator.GenericKey;

	public class JcePasswordRecipientInfoGenerator : PasswordRecipientInfoGenerator
	{
		private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());

		public JcePasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password) : base(kekAlgorithm, password)
		{
		}

		public virtual JcePasswordRecipientInfoGenerator setProvider(Provider provider)
		{
			this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

			return this;
		}

		public virtual JcePasswordRecipientInfoGenerator setProvider(string providerName)
		{
			this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

			return this;
		}

		public override byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize)
		{
			return helper.calculateDerivedKey(schemeID, password, derivationAlgorithm, keySize);
		}

		public override byte[] generateEncryptedBytes(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] derivedKey, GenericKey contentEncryptionKey)
		{
			Key contentEncryptionKeySpec = helper.getJceKey(contentEncryptionKey);
			Cipher keyEncryptionCipher = helper.createRFC3211Wrapper(keyEncryptionAlgorithm.getAlgorithm());

			try
			{
				IvParameterSpec ivSpec = new IvParameterSpec(ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets());

				keyEncryptionCipher.init(Cipher.WRAP_MODE, new SecretKeySpec(derivedKey, keyEncryptionCipher.getAlgorithm()), ivSpec);

				return keyEncryptionCipher.wrap(contentEncryptionKeySpec);
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("cannot process content encryption key: " + e.Message, e);
			}
		}
	}
}