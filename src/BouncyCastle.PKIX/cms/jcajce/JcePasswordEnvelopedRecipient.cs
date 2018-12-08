namespace org.bouncycastle.cms.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherInputStream = org.bouncycastle.jcajce.io.CipherInputStream;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;

	public class JcePasswordEnvelopedRecipient : JcePasswordRecipient
	{
		public JcePasswordEnvelopedRecipient(char[] password) : base(password)
		{
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.cms.RecipientOperator getRecipientOperator(org.bouncycastle.asn1.x509.AlgorithmIdentifier keyEncryptionAlgorithm, final org.bouncycastle.asn1.x509.AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey) throws org.bouncycastle.cms.CMSException
		public override RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey)
		{
			Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, derivedKey, encryptedContentEncryptionKey);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Cipher dataCipher = helper.createContentCipher(secretKey, contentEncryptionAlgorithm);
			Cipher dataCipher = helper.createContentCipher(secretKey, contentEncryptionAlgorithm);

			return new RecipientOperator(new InputDecryptorAnonymousInnerClass(this, contentEncryptionAlgorithm, dataCipher));
		}

		public class InputDecryptorAnonymousInnerClass : InputDecryptor
		{
			private readonly JcePasswordEnvelopedRecipient outerInstance;

			private AlgorithmIdentifier contentEncryptionAlgorithm;
			private Cipher dataCipher;

			public InputDecryptorAnonymousInnerClass(JcePasswordEnvelopedRecipient outerInstance, AlgorithmIdentifier contentEncryptionAlgorithm, Cipher dataCipher)
			{
				this.outerInstance = outerInstance;
				this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
				this.dataCipher = dataCipher;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return contentEncryptionAlgorithm;
			}

			public InputStream getInputStream(InputStream dataOut)
			{
				return new CipherInputStream(dataOut, dataCipher);
			}
		}
	}

}