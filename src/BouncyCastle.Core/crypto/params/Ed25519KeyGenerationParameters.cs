using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class Ed25519KeyGenerationParameters : KeyGenerationParameters
	{
		public Ed25519KeyGenerationParameters(SecureRandom random) : base(random, 256)
		{
		}
	}

}