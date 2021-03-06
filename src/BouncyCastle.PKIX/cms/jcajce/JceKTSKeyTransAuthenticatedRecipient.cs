﻿namespace org.bouncycastle.cms.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using MacOutputStream = org.bouncycastle.jcajce.io.MacOutputStream;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using JceGenericKey = org.bouncycastle.@operator.jcajce.JceGenericKey;


	/// <summary>
	/// the KeyTransRecipient class for a recipient who has been sent secret
	/// key material encrypted using their public key that needs to be used to
	/// derive a key and authenticate a message.
	/// </summary>
	public class JceKTSKeyTransAuthenticatedRecipient : JceKTSKeyTransRecipient
	{
		public JceKTSKeyTransAuthenticatedRecipient(PrivateKey recipientKey, KeyTransRecipientId recipientId) : base(recipientKey, getPartyVInfoFromRID(recipientId))
		{
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.cms.RecipientOperator getRecipientOperator(org.bouncycastle.asn1.x509.AlgorithmIdentifier keyEncryptionAlgorithm, final org.bouncycastle.asn1.x509.AlgorithmIdentifier contentMacAlgorithm, byte[] encryptedContentEncryptionKey) throws org.bouncycastle.cms.CMSException
		public override RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentMacAlgorithm, byte[] encryptedContentEncryptionKey)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, encryptedContentEncryptionKey);
			Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, encryptedContentEncryptionKey);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Mac dataMac = contentHelper.createContentMac(secretKey, contentMacAlgorithm);
			Mac dataMac = contentHelper.createContentMac(secretKey, contentMacAlgorithm);

			return new RecipientOperator(new MacCalculatorAnonymousInnerClass(this, contentMacAlgorithm, secretKey, dataMac));
		}

		public class MacCalculatorAnonymousInnerClass : MacCalculator
		{
			private readonly JceKTSKeyTransAuthenticatedRecipient outerInstance;

			private AlgorithmIdentifier contentMacAlgorithm;
			private Key secretKey;
			private Mac dataMac;

			public MacCalculatorAnonymousInnerClass(JceKTSKeyTransAuthenticatedRecipient outerInstance, AlgorithmIdentifier contentMacAlgorithm, Key secretKey, Mac dataMac)
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