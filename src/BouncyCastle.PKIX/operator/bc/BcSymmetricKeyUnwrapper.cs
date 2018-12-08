namespace org.bouncycastle.@operator.bc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using Wrapper = org.bouncycastle.crypto.Wrapper;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;

	public class BcSymmetricKeyUnwrapper : SymmetricKeyUnwrapper
	{
		private SecureRandom random;
		private Wrapper wrapper;
		private KeyParameter wrappingKey;

		public BcSymmetricKeyUnwrapper(AlgorithmIdentifier wrappingAlgorithm, Wrapper wrapper, KeyParameter wrappingKey) : base(wrappingAlgorithm)
		{

			this.wrapper = wrapper;
			this.wrappingKey = wrappingKey;
		}

		public virtual BcSymmetricKeyUnwrapper setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public override GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
		{
			wrapper.init(false, wrappingKey);

			try
			{
				return new GenericKey(encryptedKeyAlgorithm, wrapper.unwrap(encryptedKey, 0, encryptedKey.Length));
			}
			catch (InvalidCipherTextException e)
			{
				throw new OperatorException("unable to unwrap key: " + e.Message, e);
			}
		}
	}

}