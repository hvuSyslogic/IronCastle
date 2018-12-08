using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.generators
{

	using X448PrivateKeyParameters = org.bouncycastle.crypto.@params.X448PrivateKeyParameters;
	using X448PublicKeyParameters = org.bouncycastle.crypto.@params.X448PublicKeyParameters;

	public class X448KeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private SecureRandom random;

		public virtual void init(KeyGenerationParameters parameters)
		{
			this.random = parameters.getRandom();
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			X448PrivateKeyParameters privateKey = new X448PrivateKeyParameters(random);
			X448PublicKeyParameters publicKey = privateKey.generatePublicKey();
			return new AsymmetricCipherKeyPair(publicKey, privateKey);
		}
	}

}