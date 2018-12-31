using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.generators
{

		
	public class X25519KeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private SecureRandom random;

		public virtual void init(KeyGenerationParameters parameters)
		{
			this.random = parameters.getRandom();
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(random);
			X25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
			return new AsymmetricCipherKeyPair(publicKey, privateKey);
		}
	}

}