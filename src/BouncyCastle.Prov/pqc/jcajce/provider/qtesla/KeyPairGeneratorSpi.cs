namespace org.bouncycastle.pqc.jcajce.provider.qtesla
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using QTESLAKeyGenerationParameters = org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
	using QTESLAKeyPairGenerator = org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
	using QTESLAPrivateKeyParameters = org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
	using QTESLAPublicKeyParameters = org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
	using QTESLASecurityCategory = org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
	using QTESLAParameterSpec = org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;

	public class KeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		private static readonly Map catLookup = new HashMap();

		static KeyPairGeneratorSpi()
		{
			catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_I), QTESLASecurityCategory.HEURISTIC_I);
			catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SIZE), QTESLASecurityCategory.HEURISTIC_III_SIZE);
			catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SPEED), QTESLASecurityCategory.HEURISTIC_III_SPEED);
			catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_I), QTESLASecurityCategory.PROVABLY_SECURE_I);
			catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_III), QTESLASecurityCategory.PROVABLY_SECURE_III);
		}

		private QTESLAKeyGenerationParameters param;
		private QTESLAKeyPairGenerator engine = new QTESLAKeyPairGenerator();

		private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
		private bool initialised = false;

		public KeyPairGeneratorSpi() : base("qTESLA")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			throw new IllegalArgumentException("use AlgorithmParameterSpec");
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(@params is QTESLAParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("parameter object not a QTESLAParameterSpec");
			}

			QTESLAParameterSpec qteslaParams = (QTESLAParameterSpec)@params;

			param = new QTESLAKeyGenerationParameters((int?)catLookup.get(qteslaParams.getSecurityCategory()).Value, random);

			engine.init(param);
			initialised = true;
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				param = new QTESLAKeyGenerationParameters(QTESLASecurityCategory.PROVABLY_SECURE_I, random);

				engine.init(param);
				initialised = true;
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			QTESLAPublicKeyParameters pub = (QTESLAPublicKeyParameters)pair.getPublic();
			QTESLAPrivateKeyParameters priv = (QTESLAPrivateKeyParameters)pair.getPrivate();

			return new KeyPair(new BCqTESLAPublicKey(pub), new BCqTESLAPrivateKey(priv));
		}
	}

}