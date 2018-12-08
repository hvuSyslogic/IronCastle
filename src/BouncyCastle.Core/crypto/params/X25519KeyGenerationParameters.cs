using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class X25519KeyGenerationParameters : KeyGenerationParameters
	{
		public X25519KeyGenerationParameters(SecureRandom random) : base(random, 255)
		{
		}
	}

}