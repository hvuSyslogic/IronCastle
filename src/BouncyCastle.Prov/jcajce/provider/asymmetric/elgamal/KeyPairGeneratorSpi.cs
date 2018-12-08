namespace org.bouncycastle.jcajce.provider.asymmetric.elgamal
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using ElGamalKeyPairGenerator = org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
	using ElGamalParametersGenerator = org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
	using ElGamalKeyGenerationParameters = org.bouncycastle.crypto.@params.ElGamalKeyGenerationParameters;
	using ElGamalParameters = org.bouncycastle.crypto.@params.ElGamalParameters;
	using ElGamalPrivateKeyParameters = org.bouncycastle.crypto.@params.ElGamalPrivateKeyParameters;
	using ElGamalPublicKeyParameters = org.bouncycastle.crypto.@params.ElGamalPublicKeyParameters;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ElGamalParameterSpec = org.bouncycastle.jce.spec.ElGamalParameterSpec;

	public class KeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		internal ElGamalKeyGenerationParameters param;
		internal ElGamalKeyPairGenerator engine = new ElGamalKeyPairGenerator();
		internal int strength = 1024;
		internal int certainty = 20;
		internal SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
		internal bool initialised = false;

		public KeyPairGeneratorSpi() : base("ElGamal")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			this.strength = strength;
			this.random = random;
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(@params is ElGamalParameterSpec) && !(@params is DHParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec or an ElGamalParameterSpec");
			}

			if (@params is ElGamalParameterSpec)
			{
				ElGamalParameterSpec elParams = (ElGamalParameterSpec)@params;

				param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(elParams.getP(), elParams.getG()));
			}
			else
			{
				DHParameterSpec dhParams = (DHParameterSpec)@params;

				param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(dhParams.getP(), dhParams.getG(), dhParams.getL()));
			}

			engine.init(param);
			initialised = true;
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				DHParameterSpec dhParams = BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(strength);

				if (dhParams != null)
				{
					param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(dhParams.getP(), dhParams.getG(), dhParams.getL()));
				}
				else
				{
					ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();

					pGen.init(strength, certainty, random);
					param = new ElGamalKeyGenerationParameters(random, pGen.generateParameters());
				}

				engine.init(param);
				initialised = true;
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			ElGamalPublicKeyParameters pub = (ElGamalPublicKeyParameters)pair.getPublic();
			ElGamalPrivateKeyParameters priv = (ElGamalPrivateKeyParameters)pair.getPrivate();

			return new KeyPair(new BCElGamalPublicKey(pub), new BCElGamalPrivateKey(priv));
		}
	}


}