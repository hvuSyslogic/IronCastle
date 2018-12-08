using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	public class DHPublicKeyParameters : DHKeyParameters
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);
		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		private BigInteger y;

		public DHPublicKeyParameters(BigInteger y, DHParameters @params) : base(false, @params)
		{

			this.y = validate(y, @params);
		}

		private BigInteger validate(BigInteger y, DHParameters dhParams)
		{
			if (y == null)
			{
				throw new NullPointerException("y value cannot be null");
			}

			// TLS check
			if (y.compareTo(TWO) < 0 || y.compareTo(dhParams.getP().subtract(TWO)) > 0)
			{
				throw new IllegalArgumentException("invalid DH public key");
			}

			if (dhParams.getQ() != null)
			{
				if (ONE.Equals(y.modPow(dhParams.getQ(), dhParams.getP())))
				{
					return y;
				}

				throw new IllegalArgumentException("Y value does not appear to be in correct group");
			}
			else
			{
				return y; // we can't validate without Q.
			}
		}

		public virtual BigInteger getY()
		{
			return y;
		}

		public override int GetHashCode()
		{
			return y.GetHashCode() ^ base.GetHashCode();
		}

		public override bool Equals(object obj)
		{
			if (!(obj is DHPublicKeyParameters))
			{
				return false;
			}

			DHPublicKeyParameters other = (DHPublicKeyParameters)obj;

			return other.getY().Equals(y) && base.Equals(obj);
		}
	}

}