using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class DSAKeyGenerationParameters : KeyGenerationParameters
	{
		private DSAParameters @params;

		public DSAKeyGenerationParameters(SecureRandom random, DSAParameters @params) : base(random, @params.getP().bitLength() - 1)
		{

			this.@params = @params;
		}

		public virtual DSAParameters getParameters()
		{
			return @params;
		}
	}

}