namespace org.bouncycastle.@operator.bc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Wrapper = org.bouncycastle.crypto.Wrapper;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;

	public class BcSymmetricKeyWrapper : SymmetricKeyWrapper
	{
		private SecureRandom random;
		private Wrapper wrapper;
		private KeyParameter wrappingKey;

		public BcSymmetricKeyWrapper(AlgorithmIdentifier wrappingAlgorithm, Wrapper wrapper, KeyParameter wrappingKey) : base(wrappingAlgorithm)
		{

			this.wrapper = wrapper;
			this.wrappingKey = wrappingKey;
		}

		public virtual BcSymmetricKeyWrapper setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public override byte[] generateWrappedKey(GenericKey encryptionKey)
		{
			byte[] contentEncryptionKeySpec = OperatorUtils.getKeyBytes(encryptionKey);

			if (random == null)
			{
				wrapper.init(true, wrappingKey);
			}
			else
			{
				wrapper.init(true, new ParametersWithRandom(wrappingKey, random));
			}

			return wrapper.wrap(contentEncryptionKeySpec, 0, contentEncryptionKeySpec.Length);
		}
	}

}