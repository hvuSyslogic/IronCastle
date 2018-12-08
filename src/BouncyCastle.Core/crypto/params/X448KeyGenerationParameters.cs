using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class X448KeyGenerationParameters : KeyGenerationParameters
	{
		public X448KeyGenerationParameters(SecureRandom random) : base(random, 448)
		{
		}
	}

}