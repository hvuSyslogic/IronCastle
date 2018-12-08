using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class DHPrivateKeyParameters : DHKeyParameters
	{
		private BigInteger x;

		public DHPrivateKeyParameters(BigInteger x, DHParameters @params) : base(true, @params)
		{

			this.x = x;
		}

		public virtual BigInteger getX()
		{
			return x;
		}

		public override int GetHashCode()
		{
			return x.GetHashCode() ^ base.GetHashCode();
		}

		public override bool Equals(object obj)
		{
			if (!(obj is DHPrivateKeyParameters))
			{
				return false;
			}

			DHPrivateKeyParameters other = (DHPrivateKeyParameters)obj;

			return other.getX().Equals(this.x) && base.Equals(obj);
		}
	}

}