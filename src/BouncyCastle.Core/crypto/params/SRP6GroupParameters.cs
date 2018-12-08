using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class SRP6GroupParameters
	{
		private BigInteger N, g;

		public SRP6GroupParameters(BigInteger N, BigInteger g)
		{
			this.N = N;
			this.g = g;
		}

		public virtual BigInteger getG()
		{
			return g;
		}

		public virtual BigInteger getN()
		{
			return N;
		}
	}

}