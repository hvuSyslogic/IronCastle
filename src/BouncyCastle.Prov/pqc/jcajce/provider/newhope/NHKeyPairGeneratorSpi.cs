namespace org.bouncycastle.pqc.jcajce.provider.newhope
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;
	using NHKeyPairGenerator = org.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
	using NHPrivateKeyParameters = org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
	using NHPublicKeyParameters = org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;

	public class NHKeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		internal NHKeyPairGenerator engine = new NHKeyPairGenerator();

		internal SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
		internal bool initialised = false;

		public NHKeyPairGeneratorSpi() : base("NH")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			if (strength != 1024)
			{
				throw new IllegalArgumentException("strength must be 1024 bits");
			}
			engine.init(new KeyGenerationParameters(random, 1024));
			initialised = true;
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			throw new InvalidAlgorithmParameterException("parameter object not recognised");
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				engine.init(new KeyGenerationParameters(random, 1024));
				initialised = true;
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			NHPublicKeyParameters pub = (NHPublicKeyParameters)pair.getPublic();
			NHPrivateKeyParameters priv = (NHPrivateKeyParameters)pair.getPrivate();

			return new KeyPair(new BCNHPublicKey(pub), new BCNHPrivateKey(priv));
		}
	}

}