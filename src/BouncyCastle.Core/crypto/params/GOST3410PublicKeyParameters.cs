using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class GOST3410PublicKeyParameters : GOST3410KeyParameters
	{
		private BigInteger y;

		public GOST3410PublicKeyParameters(BigInteger y, GOST3410Parameters @params) : base(false, @params)
		{

			this.y = y;
		}

		public virtual BigInteger getY()
		{
			return y;
		}
	}

}