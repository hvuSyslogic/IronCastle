using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;

namespace org.bouncycastle.pqc.crypto.gmss
{

	
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