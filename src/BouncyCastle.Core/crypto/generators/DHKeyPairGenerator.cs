using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.generators
{
	using DHKeyGenerationParameters = org.bouncycastle.crypto.@params.DHKeyGenerationParameters;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPrivateKeyParameters = org.bouncycastle.crypto.@params.DHPrivateKeyParameters;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;

	/// <summary>
	/// a Diffie-Hellman key pair generator.
	/// 
	/// This generates keys consistent for use in the MTI/A0 key agreement protocol
	/// as described in "Handbook of Applied Cryptography", Pages 516-519.
	/// </summary>
	public class DHKeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private DHKeyGenerationParameters param;

		public virtual void init(KeyGenerationParameters param)
		{
			this.param = (DHKeyGenerationParameters)param;
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
			DHParameters dhp = param.getParameters();

			BigInteger x = helper.calculatePrivate(dhp, param.getRandom());
			BigInteger y = helper.calculatePublic(dhp, x);

			return new AsymmetricCipherKeyPair(new DHPublicKeyParameters(y, dhp), new DHPrivateKeyParameters(x, dhp));
		}
	}

}