using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.generators
{

		
	public class Ed25519KeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private SecureRandom random;

		public virtual void init(KeyGenerationParameters parameters)
		{
			this.random = parameters.getRandom();
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(random);
			Ed25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
			return new AsymmetricCipherKeyPair(publicKey, privateKey);
		}
	}

}