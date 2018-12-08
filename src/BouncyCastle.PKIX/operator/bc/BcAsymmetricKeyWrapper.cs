namespace org.bouncycastle.@operator.bc
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;

	public abstract class BcAsymmetricKeyWrapper : AsymmetricKeyWrapper
	{
		private AsymmetricKeyParameter publicKey;
		private SecureRandom random;

		public BcAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey) : base(encAlgId)
		{

			this.publicKey = publicKey;
		}

		public virtual BcAsymmetricKeyWrapper setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public override byte[] generateWrappedKey(GenericKey encryptionKey)
		{
			AsymmetricBlockCipher keyEncryptionCipher = createAsymmetricWrapper(getAlgorithmIdentifier().getAlgorithm());

			CipherParameters @params = publicKey;
			if (random != null)
			{
				@params = new ParametersWithRandom(@params, random);
			}

			try
			{
				byte[] keyEnc = OperatorUtils.getKeyBytes(encryptionKey);
				keyEncryptionCipher.init(true, @params);
				return keyEncryptionCipher.processBlock(keyEnc, 0, keyEnc.Length);
			}
			catch (InvalidCipherTextException e)
			{
				throw new OperatorException("unable to encrypt contents key", e);
			}
		}

		public abstract AsymmetricBlockCipher createAsymmetricWrapper(ASN1ObjectIdentifier algorithm);
	}

}