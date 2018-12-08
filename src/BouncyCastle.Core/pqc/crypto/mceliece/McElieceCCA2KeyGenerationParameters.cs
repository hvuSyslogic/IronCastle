using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;

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