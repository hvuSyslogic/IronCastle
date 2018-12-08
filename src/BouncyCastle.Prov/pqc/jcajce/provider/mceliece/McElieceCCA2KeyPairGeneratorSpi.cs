namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using McElieceCCA2KeyGenerationParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
	using McElieceCCA2KeyPairGenerator = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
	using McElieceCCA2Parameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2Parameters;
	using McElieceCCA2PrivateKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
	using McElieceCCA2PublicKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
	using McElieceCCA2KeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;

	public class McElieceCCA2KeyPairGeneratorSpi : KeyPairGenerator
	{
		private McElieceCCA2KeyPairGenerator kpg;

		public McElieceCCA2KeyPairGeneratorSpi() : base("McEliece-CCA2")
		{
		}

		public virtual void initialize(AlgorithmParameterSpec @params)
		{
			kpg = new McElieceCCA2KeyPairGenerator();
			base.initialize(@params);
			McElieceCCA2KeyGenParameterSpec ecc = (McElieceCCA2KeyGenParameterSpec)@params;

			McElieceCCA2KeyGenerationParameters mccca2KGParams = new McElieceCCA2KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), new McElieceCCA2Parameters(ecc.getM(), ecc.getT(), ecc.getDigest()));
			kpg.init(mccca2KGParams);
		}

		public virtual void initialize(int keySize, SecureRandom random)
		{
			kpg = new McElieceCCA2KeyPairGenerator();

			McElieceCCA2KeyGenerationParameters mccca2KGParams = new McElieceCCA2KeyGenerationParameters(random, new McElieceCCA2Parameters());
			kpg.init(mccca2KGParams);
		}

		public virtual KeyPair generateKeyPair()
		{
			AsymmetricCipherKeyPair generateKeyPair = kpg.generateKeyPair();
			McElieceCCA2PrivateKeyParameters sk = (McElieceCCA2PrivateKeyParameters)generateKeyPair.getPrivate();
			McElieceCCA2PublicKeyParameters pk = (McElieceCCA2PublicKeyParameters)generateKeyPair.getPublic();

			return new KeyPair(new BCMcElieceCCA2PublicKey(pk), new BCMcElieceCCA2PrivateKey(sk));
		}
	}

}