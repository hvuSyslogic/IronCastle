using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class ElGamalKeyGenerationParameters : KeyGenerationParameters
	{
		private ElGamalParameters @params;

		public ElGamalKeyGenerationParameters(SecureRandom random, ElGamalParameters @params) : base(random, getStrength(@params))
		{

			this.@params = @params;
		}

		public virtual ElGamalParameters getParameters()
		{
			return @params;
		}

		internal static int getStrength(ElGamalParameters @params)
		{
			return @params.getL() != 0 ? @params.getL() : @params.getP().bitLength();
		}
	}

}