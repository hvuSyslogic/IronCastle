using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class ElGamalPublicKeyParameters : ElGamalKeyParameters
	{
		private BigInteger y;

		public ElGamalPublicKeyParameters(BigInteger y, ElGamalParameters @params) : base(false, @params)
		{

			this.y = y;
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
			if (!(obj is ElGamalPublicKeyParameters))
			{
				return false;
			}

			ElGamalPublicKeyParameters other = (ElGamalPublicKeyParameters)obj;

			return other.getY().Equals(y) && base.Equals(obj);
		}
	}

}