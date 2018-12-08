namespace org.bouncycastle.cms.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using MacOutputStream = org.bouncycastle.jcajce.io.MacOutputStream;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using JceGenericKey = org.bouncycastle.@operator.jcajce.JceGenericKey;

	public class JcePasswordAuthenticatedRecipient : JcePasswordRecipient
	{
		public JcePasswordAuthenticatedRecipient(char[] password) : base(password)
		{
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.cms.RecipientOperator getRecipientOperator(org.bouncycastle.asn1.x509.AlgorithmIdentifier keyEncryptionAlgorithm, final org.bouncycastle.asn1.x509.AlgorithmIdentifier contentMacAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey) throws org.bouncycastle.cms.CMSException
		public override RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentMacAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, derivedKey, encryptedContentEncryptionKey);
			Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, derivedKey, encryptedContentEncryptionKey);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Mac dataMac = helper.createContentMac(secretKey, contentMacAlgorithm);
			Mac dataMac = helper.createContentMac(secretKey, contentMacAlgorithm);

			return new RecipientOperator(new MacCalculatorAnonymousInnerClass(this, contentMacAlgorithm, secretKey, dataMac));
		}

		public class MacCalculatorAnonymousInnerClass : MacCalculator
		{
			private readonly JcePasswordAuthenticatedRecipient outerInstance;

			private AlgorithmIdentifier contentMacAlgorithm;
			private Key secretKey;
			private Mac dataMac;

			public MacCalculatorAnonymousInnerClass(JcePasswordAuthenticatedRecipient outerInstance, AlgorithmIdentifier contentMacAlgorithm, Key secretKey, Mac dataMac)
			{
				this.outerInstance = outerInstance;
				this.contentMacAlgorithm = contentMacAlgorithm;
				this.secretKey = secretKey;
				this.dataMac = dataMac;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return contentMacAlgorithm;
			}

			public GenericKey getKey()
			{
				return new JceGenericKey(contentMacAlgorithm, secretKey);
			}

			public OutputStream getOutputStream()
			{
				return new MacOutputStream(dataMac);
			}

			public byte[] getMac()
			{
				return dataMac.doFinal();
			}
		}
	}

}