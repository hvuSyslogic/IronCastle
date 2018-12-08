using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class DHKeyGenerationParameters : KeyGenerationParameters
	{
		private DHParameters @params;

		public DHKeyGenerationParameters(SecureRandom random, DHParameters @params) : base(random, getStrength(@params))
		{

			this.@params = @params;
		}

		public virtual DHParameters getParameters()
		{
			return @params;
		}

		internal static int getStrength(DHParameters @params)
		{
			return @params.getL() != 0 ? @params.getL() : @params.getP().bitLength();
		}
	}

}