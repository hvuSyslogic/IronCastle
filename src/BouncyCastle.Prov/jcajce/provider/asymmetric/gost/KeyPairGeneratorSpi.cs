using org.bouncycastle.asn1.cryptopro;

namespace org.bouncycastle.jcajce.provider.asymmetric.gost
{

	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using GOST3410KeyPairGenerator = org.bouncycastle.crypto.generators.GOST3410KeyPairGenerator;
	using GOST3410KeyGenerationParameters = org.bouncycastle.crypto.@params.GOST3410KeyGenerationParameters;
	using GOST3410Parameters = org.bouncycastle.crypto.@params.GOST3410Parameters;
	using GOST3410PrivateKeyParameters = org.bouncycastle.crypto.@params.GOST3410PrivateKeyParameters;
	using GOST3410PublicKeyParameters = org.bouncycastle.crypto.@params.GOST3410PublicKeyParameters;
	using GOST3410ParameterSpec = org.bouncycastle.jce.spec.GOST3410ParameterSpec;
	using GOST3410PublicKeyParameterSetSpec = org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

	public class KeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		internal GOST3410KeyGenerationParameters param;
		internal GOST3410KeyPairGenerator engine = new GOST3410KeyPairGenerator();
		internal GOST3410ParameterSpec gost3410Params;
		internal int strength = 1024;
		internal SecureRandom random = null;
		internal bool initialised = false;

		public KeyPairGeneratorSpi() : base("GOST3410")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			this.strength = strength;
			this.random = random;
		}

		private void init(GOST3410ParameterSpec gParams, SecureRandom random)
		{
			GOST3410PublicKeyParameterSetSpec spec = gParams.getPublicKeyParameters();

			param = new GOST3410KeyGenerationParameters(random, new GOST3410Parameters(spec.getP(), spec.getQ(), spec.getA()));

			engine.init(param);

			initialised = true;
			gost3410Params = gParams;
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(@params is GOST3410ParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("parameter object not a GOST3410ParameterSpec");
			}

			init((GOST3410ParameterSpec)@params, random);
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				init(new GOST3410ParameterSpec(CryptoProObjectIdentifiers_Fields.gostR3410_94_CryptoPro_A.getId()), CryptoServicesRegistrar.getSecureRandom());
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			GOST3410PublicKeyParameters pub = (GOST3410PublicKeyParameters)pair.getPublic();
			GOST3410PrivateKeyParameters priv = (GOST3410PrivateKeyParameters)pair.getPrivate();

			return new KeyPair(new BCGOST3410PublicKey(pub, gost3410Params), new BCGOST3410PrivateKey(priv, gost3410Params));
		}
	}

}