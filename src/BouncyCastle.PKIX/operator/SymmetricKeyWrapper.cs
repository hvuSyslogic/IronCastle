namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public abstract class SymmetricKeyWrapper : KeyWrapper
	{
		public abstract byte[] generateWrappedKey(GenericKey encryptionKey);
		private AlgorithmIdentifier algorithmId;

		public SymmetricKeyWrapper(AlgorithmIdentifier algorithmId)
		{
			this.algorithmId = algorithmId;
		}

		public virtual AlgorithmIdentifier getAlgorithmIdentifier()
		{
			return algorithmId;
		}
	}

}