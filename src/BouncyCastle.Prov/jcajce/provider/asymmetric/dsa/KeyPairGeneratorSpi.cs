namespace org.bouncycastle.jcajce.provider.asymmetric.dsa
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using DSAKeyPairGenerator = org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
	using DSAParametersGenerator = org.bouncycastle.crypto.generators.DSAParametersGenerator;
	using DSAKeyGenerationParameters = org.bouncycastle.crypto.@params.DSAKeyGenerationParameters;
	using DSAParameterGenerationParameters = org.bouncycastle.crypto.@params.DSAParameterGenerationParameters;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPrivateKeyParameters = org.bouncycastle.crypto.@params.DSAPrivateKeyParameters;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using PrimeCertaintyCalculator = org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Integers = org.bouncycastle.util.Integers;
	using Properties = org.bouncycastle.util.Properties;

	public class KeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		private static Hashtable @params = new Hashtable();
		private static object @lock = new object();

		internal DSAKeyGenerationParameters param;
		internal DSAKeyPairGenerator engine = new DSAKeyPairGenerator();
		internal int strength = 2048;
		internal SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
		internal bool initialised = false;

		public KeyPairGeneratorSpi() : base("DSA")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			if (strength < 512 || strength > 4096 || ((strength < 1024) && strength % 64 != 0) || (strength >= 1024 && strength % 1024 != 0))
			{
				throw new InvalidParameterException("strength must be from 512 - 4096 and a multiple of 1024 above 1024");
			}

			DSAParameterSpec spec = BouncyCastleProvider.CONFIGURATION.getDSADefaultParameters(strength);

			if (spec != null)
			{
				param = new DSAKeyGenerationParameters(random, new DSAParameters(spec.getP(), spec.getQ(), spec.getG()));

				engine.init(param);
				this.initialised = true;
			}
			else
			{
				this.strength = strength;
				this.random = random;
				this.initialised = false;
			}
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(@params is DSAParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("parameter object not a DSAParameterSpec");
			}
			DSAParameterSpec dsaParams = (DSAParameterSpec)@params;

			param = new DSAKeyGenerationParameters(random, new DSAParameters(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG()));

			engine.init(param);
			initialised = true;
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				int? paramStrength = Integers.valueOf(strength);

				if (@params.containsKey(paramStrength))
				{
					param = (DSAKeyGenerationParameters)@params.get(paramStrength);
				}
				else
				{
					lock (@lock)
					{
						// we do the check again in case we were blocked by a generator for
						// our key size.
						if (@params.containsKey(paramStrength))
						{
							param = (DSAKeyGenerationParameters)@params.get(paramStrength);
						}
						else
						{
							DSAParametersGenerator pGen;
							DSAParameterGenerationParameters dsaParams;

							int certainty = PrimeCertaintyCalculator.getDefaultCertainty(strength);

							// Typical combination of keysize and size of q.
							//     keysize = 1024, q's size = 160
							//     keysize = 2048, q's size = 224
							//     keysize = 2048, q's size = 256
							//     keysize = 3072, q's size = 256
							// For simplicity if keysize is greater than 1024 then we choose q's size to be 256.
							// For legacy keysize that is less than 1024-bit, we just use the 186-2 style parameters
							if (strength == 1024)
							{
								pGen = new DSAParametersGenerator();
								if (Properties.isOverrideSet("org.bouncycastle.dsa.FIPS186-2for1024bits"))
								{
									pGen.init(strength, certainty, random);
								}
								else
								{
									dsaParams = new DSAParameterGenerationParameters(1024, 160, certainty, random);
									pGen.init(dsaParams);
								}
							}
							else if (strength > 1024)
							{
								dsaParams = new DSAParameterGenerationParameters(strength, 256, certainty, random);
								pGen = new DSAParametersGenerator(new SHA256Digest());
								pGen.init(dsaParams);
							}
							else
							{
								pGen = new DSAParametersGenerator();
								pGen.init(strength, certainty, random);
							}
							param = new DSAKeyGenerationParameters(random, pGen.generateParameters());

							@params.put(paramStrength, param);
						}
					}
				}

				engine.init(param);
				initialised = true;
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			DSAPublicKeyParameters pub = (DSAPublicKeyParameters)pair.getPublic();
			DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)pair.getPrivate();

			return new KeyPair(new BCDSAPublicKey(pub), new BCDSAPrivateKey(priv));
		}
	}

}