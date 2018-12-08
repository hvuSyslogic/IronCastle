namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using McElieceKeyGenerationParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceKeyGenerationParameters;
	using McElieceKeyPairGenerator = org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator;
	using McElieceParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceParameters;
	using McEliecePrivateKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
	using McEliecePublicKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
	using McElieceKeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;

	public class McElieceKeyPairGeneratorSpi : KeyPairGenerator
	{
		internal McElieceKeyPairGenerator kpg;

		public McElieceKeyPairGeneratorSpi() : base("McEliece")
		{
		}

		public virtual void initialize(AlgorithmParameterSpec @params)
		{
			kpg = new McElieceKeyPairGenerator();
			base.initialize(@params);
			McElieceKeyGenParameterSpec ecc = (McElieceKeyGenParameterSpec)@params;

			McElieceKeyGenerationParameters mccKGParams = new McElieceKeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), new McElieceParameters(ecc.getM(), ecc.getT()));
			kpg.init(mccKGParams);
		}

		public virtual void initialize(int keySize, SecureRandom random)
		{
			McElieceKeyGenParameterSpec paramSpec = new McElieceKeyGenParameterSpec();

			// call the initializer with the chosen parameters
			try
			{
				this.initialize(paramSpec);
			}
			catch (InvalidAlgorithmParameterException)
			{
			}
		}

		public virtual KeyPair generateKeyPair()
		{
			AsymmetricCipherKeyPair generateKeyPair = kpg.generateKeyPair();
			McEliecePrivateKeyParameters sk = (McEliecePrivateKeyParameters)generateKeyPair.getPrivate();
			McEliecePublicKeyParameters pk = (McEliecePublicKeyParameters)generateKeyPair.getPublic();

			return new KeyPair(new BCMcEliecePublicKey(pk), new BCMcEliecePrivateKey(sk));
		}

	}

}