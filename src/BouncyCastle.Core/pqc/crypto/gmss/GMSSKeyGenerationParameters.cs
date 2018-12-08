using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.crypto.gmss
{

	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;

	public class GMSSKeyGenerationParameters : KeyGenerationParameters
	{

		private GMSSParameters @params;

		public GMSSKeyGenerationParameters(SecureRandom random, GMSSParameters @params) : base(random, 1)
		{
			// XXX key size?
			this.@params = @params;
		}

		public virtual GMSSParameters getParameters()
		{
			return @params;
		}
	}

}