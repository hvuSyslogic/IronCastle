namespace org.bouncycastle.jcajce.provider.asymmetric.dh
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using DHBasicKeyPairGenerator = org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
	using DHParametersGenerator = org.bouncycastle.crypto.generators.DHParametersGenerator;
	using DHKeyGenerationParameters = org.bouncycastle.crypto.@params.DHKeyGenerationParameters;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPrivateKeyParameters = org.bouncycastle.crypto.@params.DHPrivateKeyParameters;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;
	using PrimeCertaintyCalculator = org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
	using DHDomainParameterSpec = org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Integers = org.bouncycastle.util.Integers;

	public class KeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		private static Hashtable @params = new Hashtable();
		private static object @lock = new object();

		internal DHKeyGenerationParameters param;
		internal DHBasicKeyPairGenerator engine = new DHBasicKeyPairGenerator();
		internal int strength = 2048;
		internal SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
		internal bool initialised = false;

		public KeyPairGeneratorSpi() : base("DH")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			this.strength = strength;
			this.random = random;
			this.initialised = false;
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(@params is DHParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec");
			}
			DHParameterSpec dhParams = (DHParameterSpec)@params;

			try
			{
				param = convertParams(random, dhParams);
			}
			catch (IllegalArgumentException e)
			{
				throw new InvalidAlgorithmParameterException(e.getMessage(), e);
			}

			engine.init(param);
			initialised = true;
		}

		private DHKeyGenerationParameters convertParams(SecureRandom random, DHParameterSpec dhParams)
		{
			if (dhParams is DHDomainParameterSpec)
			{
				return new DHKeyGenerationParameters(random, ((DHDomainParameterSpec)dhParams).getDomainParameters());
			}
			return new DHKeyGenerationParameters(random, new DHParameters(dhParams.getP(), dhParams.getG(), null, dhParams.getL()));
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				int? paramStrength = Integers.valueOf(strength);

				if (@params.containsKey(paramStrength))
				{
					param = (DHKeyGenerationParameters)@params.get(paramStrength);
				}
				else
				{
					DHParameterSpec dhParams = BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(strength);

					if (dhParams != null)
					{
						param = convertParams(random, dhParams);
					}
					else
					{
						lock (@lock)
						{
							// we do the check again in case we were blocked by a generator for
							// our key size.
							if (@params.containsKey(paramStrength))
							{
								param = (DHKeyGenerationParameters)@params.get(paramStrength);
							}
							else
							{

								DHParametersGenerator pGen = new DHParametersGenerator();

								pGen.init(strength, PrimeCertaintyCalculator.getDefaultCertainty(strength), random);

								param = new DHKeyGenerationParameters(random, pGen.generateParameters());

								@params.put(paramStrength, param);
							}
						}
					}
				}

				engine.init(param);

				initialised = true;
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			DHPublicKeyParameters pub = (DHPublicKeyParameters)pair.getPublic();
			DHPrivateKeyParameters priv = (DHPrivateKeyParameters)pair.getPrivate();

			return new KeyPair(new BCDHPublicKey(pub), new BCDHPrivateKey(priv));
		}
	}

}