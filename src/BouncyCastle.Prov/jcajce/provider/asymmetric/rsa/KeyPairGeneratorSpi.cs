namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using RSAKeyPairGenerator = org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
	using RSAKeyGenerationParameters = org.bouncycastle.crypto.@params.RSAKeyGenerationParameters;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using PrimeCertaintyCalculator = org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;

	public class KeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		public KeyPairGeneratorSpi(string algorithmName) : base(algorithmName)
		{
		}

		internal static readonly BigInteger defaultPublicExponent = BigInteger.valueOf(0x10001);

		internal RSAKeyGenerationParameters param;
		internal RSAKeyPairGenerator engine;

		public KeyPairGeneratorSpi() : base("RSA")
		{

			engine = new RSAKeyPairGenerator();
			param = new RSAKeyGenerationParameters(defaultPublicExponent, CryptoServicesRegistrar.getSecureRandom(), 2048, PrimeCertaintyCalculator.getDefaultCertainty(2048));
			engine.init(param);
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			param = new RSAKeyGenerationParameters(defaultPublicExponent, random, strength, PrimeCertaintyCalculator.getDefaultCertainty(strength));

			engine.init(param);
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(@params is RSAKeyGenParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("parameter object not a RSAKeyGenParameterSpec");
			}
			RSAKeyGenParameterSpec rsaParams = (RSAKeyGenParameterSpec)@params;

			param = new RSAKeyGenerationParameters(rsaParams.getPublicExponent(), random, rsaParams.getKeysize(), PrimeCertaintyCalculator.getDefaultCertainty(2048));

			engine.init(param);
		}

		public virtual KeyPair generateKeyPair()
		{
			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			RSAKeyParameters pub = (RSAKeyParameters)pair.getPublic();
			RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)pair.getPrivate();

			return new KeyPair(new BCRSAPublicKey(pub), new BCRSAPrivateCrtKey(priv));
		}
	}

}