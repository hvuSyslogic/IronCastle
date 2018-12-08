namespace org.bouncycastle.pqc.jcajce.provider.rainbow
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using RainbowKeyGenerationParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
	using RainbowKeyPairGenerator = org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
	using RainbowParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
	using RainbowPrivateKeyParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
	using RainbowPublicKeyParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
	using RainbowParameterSpec = org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;

	public class RainbowKeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		internal RainbowKeyGenerationParameters param;
		internal RainbowKeyPairGenerator engine = new RainbowKeyPairGenerator();
		internal int strength = 1024;
		internal SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
		internal bool initialised = false;

		public RainbowKeyPairGeneratorSpi() : base("Rainbow")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			this.strength = strength;
			this.random = random;
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(@params is RainbowParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("parameter object not a RainbowParameterSpec");
			}
			RainbowParameterSpec rainbowParams = (RainbowParameterSpec)@params;

			param = new RainbowKeyGenerationParameters(random, new RainbowParameters(rainbowParams.getVi()));

			engine.init(param);
			initialised = true;
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				param = new RainbowKeyGenerationParameters(random, new RainbowParameters((new RainbowParameterSpec()).getVi()));

				engine.init(param);
				initialised = true;
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			RainbowPublicKeyParameters pub = (RainbowPublicKeyParameters)pair.getPublic();
			RainbowPrivateKeyParameters priv = (RainbowPrivateKeyParameters)pair.getPrivate();

			return new KeyPair(new BCRainbowPublicKey(pub), new BCRainbowPrivateKey(priv));
		}
	}

}