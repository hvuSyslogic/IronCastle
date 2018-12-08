namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public abstract class AsymmetricKeyUnwrapper : KeyUnwrapper
	{
		public abstract GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptionKeyAlgorithm, byte[] encryptedKey);
		private AlgorithmIdentifier algorithmId;

		public AsymmetricKeyUnwrapper(AlgorithmIdentifier algorithmId)
		{
			this.algorithmId = algorithmId;
		}

		public virtual AlgorithmIdentifier getAlgorithmIdentifier()
		{
			return algorithmId;
		}
	}

}