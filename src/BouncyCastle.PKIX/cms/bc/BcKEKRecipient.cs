namespace org.bouncycastle.cms.bc
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using OperatorException = org.bouncycastle.@operator.OperatorException;
	using SymmetricKeyUnwrapper = org.bouncycastle.@operator.SymmetricKeyUnwrapper;
	using BcSymmetricKeyUnwrapper = org.bouncycastle.@operator.bc.BcSymmetricKeyUnwrapper;

	public abstract class BcKEKRecipient : KEKRecipient
	{
		public abstract RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey);
		private SymmetricKeyUnwrapper unwrapper;

		public BcKEKRecipient(BcSymmetricKeyUnwrapper unwrapper)
		{
			this.unwrapper = unwrapper;
		}

		public virtual CipherParameters extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
		{
			try
			{
				return CMSUtils.getBcKey(unwrapper.generateUnwrappedKey(contentEncryptionAlgorithm, encryptedContentEncryptionKey));
			}
			catch (OperatorException e)
			{
				throw new CMSException("exception unwrapping key: " + e.Message, e);
			}
		}
	}

}