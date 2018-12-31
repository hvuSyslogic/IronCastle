using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	
	public class McElieceCCA2KeyGenerationParameters : KeyGenerationParameters
	{
		private McElieceCCA2Parameters @params;

		public McElieceCCA2KeyGenerationParameters(SecureRandom random, McElieceCCA2Parameters @params) : base(random, 128)
		{
			// XXX key size?
			this.@params = @params;
		}

		public virtual McElieceCCA2Parameters getParameters()
		{
			return @params;
		}
	}

}