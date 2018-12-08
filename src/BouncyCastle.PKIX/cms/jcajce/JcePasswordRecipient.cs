using org.bouncycastle.cms;

namespace org.bouncycastle.cms.jcajce
{


	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// the RecipientInfo class for a recipient who has been sent a message
	/// encrypted using a password.
	/// </summary>
	public abstract class JcePasswordRecipient : PasswordRecipient
	{
		public abstract RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedEncryptedContentKey);
		private int schemeID = PasswordRecipient_Fields.PKCS5_SCHEME2_UTF8;
		protected internal EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
		private char[] password;

		public JcePasswordRecipient(char[] password)
		{
			this.password = password;
		}

		public virtual JcePasswordRecipient setPasswordConversionScheme(int schemeID)
		{
			this.schemeID = schemeID;

			return this;
		}

		public virtual JcePasswordRecipient setProvider(Provider provider)
		{
			this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

			return this;
		}

		public virtual JcePasswordRecipient setProvider(string providerName)
		{
			this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

			return this;
		}

		public virtual Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey)
		{
			Cipher keyEncryptionCipher = helper.createRFC3211Wrapper(keyEncryptionAlgorithm.getAlgorithm());

			try
			{
				IvParameterSpec ivSpec = new IvParameterSpec(ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets());

				keyEncryptionCipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(derivedKey, keyEncryptionCipher.getAlgorithm()), ivSpec);

				return keyEncryptionCipher.unwrap(encryptedContentEncryptionKey, contentEncryptionAlgorithm.getAlgorithm().getId(), Cipher.SECRET_KEY);
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("cannot process content encryption key: " + e.Message, e);
			}
		}

		public virtual byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize)
		{
			return helper.calculateDerivedKey(schemeID, password, derivationAlgorithm, keySize);
		}

		public virtual int getPasswordConversionScheme()
		{
			return schemeID;
		}

		public virtual char[] getPassword()
		{
			return password;
		}
	}

}