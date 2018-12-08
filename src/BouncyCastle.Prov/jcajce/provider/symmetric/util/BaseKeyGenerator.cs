namespace org.bouncycastle.jcajce.provider.symmetric.util
{


	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;

	public class BaseKeyGenerator : KeyGeneratorSpi
	{
		protected internal string algName;
		protected internal int keySize;
		protected internal int defaultKeySize;
		protected internal CipherKeyGenerator engine;

		protected internal bool uninitialised = true;

		public BaseKeyGenerator(string algName, int defaultKeySize, CipherKeyGenerator engine)
		{
			this.algName = algName;
			this.keySize = this.defaultKeySize = defaultKeySize;
			this.engine = engine;
		}

		public override void engineInit(AlgorithmParameterSpec @params, SecureRandom random)
		{
			throw new InvalidAlgorithmParameterException("Not Implemented");
		}

		public override void engineInit(SecureRandom random)
		{
			if (random != null)
			{
				engine.init(new KeyGenerationParameters(random, defaultKeySize));
				uninitialised = false;
			}
		}

		public override void engineInit(int keySize, SecureRandom random)
		{
			try
			{
				if (random == null)
				{
					random = CryptoServicesRegistrar.getSecureRandom();
				}
				engine.init(new KeyGenerationParameters(random, keySize));
				uninitialised = false;
			}
			catch (IllegalArgumentException e)
			{
				throw new InvalidParameterException(e.getMessage());
			}
		}

		public override SecretKey engineGenerateKey()
		{
			if (uninitialised)
			{
				engine.init(new KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), defaultKeySize));
				uninitialised = false;
			}

			return new SecretKeySpec(engine.generateKey(), algName);
		}
	}

}