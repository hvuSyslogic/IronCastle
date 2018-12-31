using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.generators
{

		
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