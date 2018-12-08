using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class GOST3410PrivateKeyParameters : GOST3410KeyParameters
	{
		private BigInteger x;

		public GOST3410PrivateKeyParameters(BigInteger x, GOST3410Parameters @params) : base(true, @params)
		{

			this.x = x;
		}

		public virtual BigInteger getX()
		{
			return x;
		}
	}

}