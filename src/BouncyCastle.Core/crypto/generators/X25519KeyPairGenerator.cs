using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.generators
{

	using X25519PrivateKeyParameters = org.bouncycastle.crypto.@params.X25519PrivateKeyParameters;
	using X25519PublicKeyParameters = org.bouncycastle.crypto.@params.X25519PublicKeyParameters;

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