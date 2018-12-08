namespace org.bouncycastle.cms.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherInputStream = org.bouncycastle.jcajce.io.CipherInputStream;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;

	/// <summary>
	/// the KeyTransRecipient class for a recipient who has been sent secret
	/// key material encrypted using their public key that needs to be used to
	/// derive a key and extract a message.
	/// </summary>
	public class JceKTSKeyTransEnvelopedRecipient : JceKTSKeyTransRecipient
	{
		public JceKTSKeyTransEnvelopedRecipient(PrivateKey recipientKey, KeyTransRecipientId recipientId) : base(recipientKey, getPartyVInfoFromRID(recipientId))
		{
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.cms.RecipientOperator getRecipientOperator(org.bouncycastle.asn1.x509.AlgorithmIdentifier keyEncryptionAlgorithm, final org.bouncycastle.asn1.x509.AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey) throws org.bouncycastle.cms.CMSException
		public override RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
		{
			Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);
			Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);

			return new RecipientOperator(new InputDecryptorAnonymousInnerClass(this, contentEncryptionAlgorithm, dataCipher));
		}

		public class InputDecryptorAnonymousInnerClass : InputDecryptor
		{
			private readonly JceKTSKeyTransEnvelopedRecipient outerInstance;

			private AlgorithmIdentifier contentEncryptionAlgorithm;
			private Cipher dataCipher;

			public InputDecryptorAnonymousInnerClass(JceKTSKeyTransEnvelopedRecipient outerInstance, AlgorithmIdentifier contentEncryptionAlgorithm, Cipher dataCipher)
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
				return new CipherInputStream(dataIn, dataCipher);
			}
		}
	}

}