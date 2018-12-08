﻿using org.bouncycastle.crypto.io;

namespace org.bouncycastle.cms.bc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using StreamCipher = org.bouncycastle.crypto.StreamCipher;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;
	using BcSymmetricKeyUnwrapper = org.bouncycastle.@operator.bc.BcSymmetricKeyUnwrapper;

	public class BcKEKEnvelopedRecipient : BcKEKRecipient
	{
		public BcKEKEnvelopedRecipient(BcSymmetricKeyUnwrapper unwrapper) : base(unwrapper)
		{
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.cms.RecipientOperator getRecipientOperator(org.bouncycastle.asn1.x509.AlgorithmIdentifier keyEncryptionAlgorithm, final org.bouncycastle.asn1.x509.AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey) throws org.bouncycastle.cms.CMSException
		public override RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
		{
			KeyParameter secretKey = (KeyParameter)extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final Object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey, contentEncryptionAlgorithm);
			object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey, contentEncryptionAlgorithm);

			return new RecipientOperator(new InputDecryptorAnonymousInnerClass(this, contentEncryptionAlgorithm, dataCipher));
		}

		public class InputDecryptorAnonymousInnerClass : InputDecryptor
		{
			private readonly BcKEKEnvelopedRecipient outerInstance;

			private AlgorithmIdentifier contentEncryptionAlgorithm;
			private object dataCipher;

			public InputDecryptorAnonymousInnerClass(BcKEKEnvelopedRecipient outerInstance, AlgorithmIdentifier contentEncryptionAlgorithm, object dataCipher)
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
				if (dataCipher is BufferedBlockCipher)
				{
					return new CipherInputStream(dataOut, (BufferedBlockCipher)dataCipher);
				}
				else
				{
					return new CipherInputStream(dataOut, (StreamCipher)dataCipher);
				}
			}
		}
	}

}