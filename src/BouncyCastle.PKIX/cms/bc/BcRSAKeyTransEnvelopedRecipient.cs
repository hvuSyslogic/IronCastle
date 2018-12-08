namespace org.bouncycastle.cms.bc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using StreamCipher = org.bouncycastle.crypto.StreamCipher;
	using CipherInputStream = org.bouncycastle.crypto.io.CipherInputStream;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;

	public class BcRSAKeyTransEnvelopedRecipient : BcKeyTransRecipient
	{
		public BcRSAKeyTransEnvelopedRecipient(AsymmetricKeyParameter key) : base(key)
		{
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.cms.RecipientOperator getRecipientOperator(org.bouncycastle.asn1.x509.AlgorithmIdentifier keyEncryptionAlgorithm, final org.bouncycastle.asn1.x509.AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey) throws org.bouncycastle.cms.CMSException
		public override RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
		{
			CipherParameters secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final Object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey, contentEncryptionAlgorithm);
			object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey, contentEncryptionAlgorithm);

			return new RecipientOperator(new InputDecryptorAnonymousInnerClass(this, contentEncryptionAlgorithm, dataCipher));
		}

		public class InputDecryptorAnonymousInnerClass : InputDecryptor
		{
			private readonly BcRSAKeyTransEnvelopedRecipient outerInstance;

			private AlgorithmIdentifier contentEncryptionAlgorithm;
			private object dataCipher;

			public InputDecryptorAnonymousInnerClass(BcRSAKeyTransEnvelopedRecipient outerInstance, AlgorithmIdentifier contentEncryptionAlgorithm, object dataCipher)
			{
				this.outerInstance = outerInstance;
				this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
				this.dataCipher = dataCipher;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return contentEncryptionAlgorithm;
			}

			public InputStream getInputStream(InputStream dataIn)
			{
				if (dataCipher is BufferedBlockCipher)
				{
					return new CipherInputStream(dataIn, (BufferedBlockCipher)dataCipher);
				}
				else
				{
					return new CipherInputStream(dataIn, (StreamCipher)dataCipher);
				}
			}
		}
	}

}