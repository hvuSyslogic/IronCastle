using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	public class DSAPublicKeyParameters : DSAKeyParameters
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);
		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		private BigInteger y;

		public DSAPublicKeyParameters(BigInteger y, DSAParameters @params) : base(false, @params)
		{

			this.y = validate(y, @params);
		}

		private BigInteger validate(BigInteger y, DSAParameters @params)
		{
			if (@params != null)
			{
				if (TWO.compareTo(y) <= 0 && @params.getP().subtract(TWO).compareTo(y) >= 0 && ONE.Equals(y.modPow(@params.getQ(), @params.getP())))
				{
					return y;
				}

				throw new IllegalArgumentException("y value does not appear to be in correct group");
			}
			else
			{
				return y; // we can't validate without params, fortunately we can't use the key either...
			}
		}

		public virtual BigInteger getY()
		{
			return y;
		}
	}

}