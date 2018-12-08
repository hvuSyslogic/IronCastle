using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class ElGamalPrivateKeyParameters : ElGamalKeyParameters
	{
		private BigInteger x;

		public ElGamalPrivateKeyParameters(BigInteger x, ElGamalParameters @params) : base(true, @params)
		{

			this.x = x;
		}

		public virtual BigInteger getX()
		{
			return x;
		}

		public override bool Equals(object obj)
		{
			if (!(obj is ElGamalPrivateKeyParameters))
			{
				return false;
			}

			ElGamalPrivateKeyParameters pKey = (ElGamalPrivateKeyParameters)obj;

			if (!pKey.getX().Equals(x))
			{
				return false;
			}

			return base.Equals(obj);
		}

		public override int GetHashCode()
		{
			return getX().GetHashCode();
		}
	}

}