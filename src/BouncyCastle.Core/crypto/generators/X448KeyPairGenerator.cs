using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.generators
{

		
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