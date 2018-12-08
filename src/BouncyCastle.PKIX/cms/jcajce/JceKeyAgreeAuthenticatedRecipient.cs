namespace org.bouncycastle.cms.jcajce
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using MacOutputStream = org.bouncycastle.jcajce.io.MacOutputStream;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using JceGenericKey = org.bouncycastle.@operator.jcajce.JceGenericKey;

	public class JceKeyAgreeAuthenticatedRecipient : JceKeyAgreeRecipient
	{
		public JceKeyAgreeAuthenticatedRecipient(PrivateKey recipientKey) : base(recipientKey)
		{
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.cms.RecipientOperator getRecipientOperator(org.bouncycastle.asn1.x509.AlgorithmIdentifier keyEncryptionAlgorithm, final org.bouncycastle.asn1.x509.AlgorithmIdentifier contentMacAlgorithm, org.bouncycastle.asn1.x509.SubjectPublicKeyInfo senderPublicKey, org.bouncycastle.asn1.ASN1OctetString userKeyingMaterial, byte[] encryptedContentKey) throws org.bouncycastle.cms.CMSException
		public override RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentMacAlgorithm, SubjectPublicKeyInfo senderPublicKey, ASN1OctetString userKeyingMaterial, byte[] encryptedContentKey)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, senderPublicKey, userKeyingMaterial, encryptedContentKey);
			Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, senderPublicKey, userKeyingMaterial, encryptedContentKey);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Mac dataMac = contentHelper.createContentMac(secretKey, contentMacAlgorithm);
			Mac dataMac = contentHelper.createContentMac(secretKey, contentMacAlgorithm);

			return new RecipientOperator(new MacCalculatorAnonymousInnerClass(this, contentMacAlgorithm, secretKey, dataMac));
		}

		public class MacCalculatorAnonymousInnerClass : MacCalculator
		{
			private readonly JceKeyAgreeAuthenticatedRecipient outerInstance;

			private AlgorithmIdentifier contentMacAlgorithm;
			private Key secretKey;
			private Mac dataMac;

			public MacCalculatorAnonymousInnerClass(JceKeyAgreeAuthenticatedRecipient outerInstance, AlgorithmIdentifier contentMacAlgorithm, Key secretKey, Mac dataMac)
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