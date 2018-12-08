using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.generators
{

	using Ed448PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed448PrivateKeyParameters;
	using Ed448PublicKeyParameters = org.bouncycastle.crypto.@params.Ed448PublicKeyParameters;

	public class Ed448KeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private SecureRandom random;

		public virtual void init(KeyGenerationParameters parameters)
		{
			this.random = parameters.getRandom();
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(random);
			Ed448PublicKeyParameters publicKey = privateKey.generatePublicKey();
			return new AsymmetricCipherKeyPair(publicKey, privateKey);
		}
	}

}