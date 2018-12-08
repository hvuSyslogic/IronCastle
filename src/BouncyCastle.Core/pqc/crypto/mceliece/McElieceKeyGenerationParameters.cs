using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;

	public class McElieceKeyGenerationParameters : KeyGenerationParameters
	{
		private McElieceParameters @params;

		public McElieceKeyGenerationParameters(SecureRandom random, McElieceParameters @params) : base(random, 256)
		{
			// XXX key size?
			this.@params = @params;
		}

		public virtual McElieceParameters getParameters()
		{
			return @params;
		}
	}

}