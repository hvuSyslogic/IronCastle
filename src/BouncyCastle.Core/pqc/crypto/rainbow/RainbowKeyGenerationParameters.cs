using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;

namespace org.bouncycastle.pqc.crypto.rainbow
{

	
	public class RainbowKeyGenerationParameters : KeyGenerationParameters
	{
		private RainbowParameters @params;

		public RainbowKeyGenerationParameters(SecureRandom random, RainbowParameters @params) : base(random, @params.getVi()[@params.getVi().Length - 1] - @params.getVi()[0])
		{
			// TODO: key size?
			this.@params = @params;
		}

		public virtual RainbowParameters getParameters()
		{
			return @params;
		}
	}


}