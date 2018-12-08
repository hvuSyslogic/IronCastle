using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class Ed448KeyGenerationParameters : KeyGenerationParameters
	{
		public Ed448KeyGenerationParameters(SecureRandom random) : base(random, 448)
		{
		}
	}

}