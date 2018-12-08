namespace org.bouncycastle.cms.jcajce
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherInputStream = org.bouncycastle.jcajce.io.CipherInputStream;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;

	public class JceKeyAgreeEnvelopedRecipient : JceKeyAgreeRecipient
	{
		public JceKeyAgreeEnvelopedRecipient(PrivateKey recipientKey) : base(recipientKey)
		{
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.cms.RecipientOperator getRecipientOperator(org.bouncycastle.asn1.x509.AlgorithmIdentifier keyEncryptionAlgorithm, final org.bouncycastle.asn1.x509.AlgorithmIdentifier contentEncryptionAlgorithm, org.bouncycastle.asn1.x509.SubjectPublicKeyInfo senderPublicKey, org.bouncycastle.asn1.ASN1OctetString userKeyingMaterial, byte[] encryptedContentKey) throws org.bouncycastle.cms.CMSException
		public override RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, SubjectPublicKeyInfo senderPublicKey, ASN1OctetString userKeyingMaterial, byte[] encryptedContentKey)
		{
			Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, senderPublicKey, userKeyingMaterial, encryptedContentKey);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);
			Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);

			return new RecipientOperator(new InputDecryptorAnonymousInnerClass(this, contentEncryptionAlgorithm, dataCipher));
		}

		public class InputDecryptorAnonymousInnerClass : InputDecryptor
		{
			private readonly JceKeyAgreeEnvelopedRecipient outerInstance;

			private AlgorithmIdentifier contentEncryptionAlgorithm;
			private Cipher dataCipher;

			public InputDecryptorAnonymousInnerClass(JceKeyAgreeEnvelopedRecipient outerInstance, AlgorithmIdentifier contentEncryptionAlgorithm, Cipher dataCipher)
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