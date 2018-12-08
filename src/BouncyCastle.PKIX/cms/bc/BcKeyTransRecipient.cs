namespace org.bouncycastle.cms.bc
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using AsymmetricKeyUnwrapper = org.bouncycastle.@operator.AsymmetricKeyUnwrapper;
	using OperatorException = org.bouncycastle.@operator.OperatorException;
	using BcRSAAsymmetricKeyUnwrapper = org.bouncycastle.@operator.bc.BcRSAAsymmetricKeyUnwrapper;

	public abstract class BcKeyTransRecipient : KeyTransRecipient
	{
		public abstract RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey);
		private AsymmetricKeyParameter recipientKey;

		public BcKeyTransRecipient(AsymmetricKeyParameter recipientKey)
		{
			this.recipientKey = recipientKey;
		}

		public virtual CipherParameters extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
		{
			AsymmetricKeyUnwrapper unwrapper = new BcRSAAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, recipientKey);

			try
			{
				return CMSUtils.getBcKey(unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));
			}
			catch (OperatorException e)
			{
				throw new CMSException("exception unwrapping key: " + e.Message, e);
			}
		}
	}

}