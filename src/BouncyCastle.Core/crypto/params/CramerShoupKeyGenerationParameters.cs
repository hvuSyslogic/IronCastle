using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class CramerShoupKeyGenerationParameters : KeyGenerationParameters
	{

		private CramerShoupParameters @params;

		public CramerShoupKeyGenerationParameters(SecureRandom random, CramerShoupParameters @params) : base(random, getStrength(@params))
		{

			this.@params = @params;
		}

		public virtual CramerShoupParameters getParameters()
		{
			return @params;
		}

		internal static int getStrength(CramerShoupParameters @params)
		{
			return @params.getP().bitLength();
		}
	}

}