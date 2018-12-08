using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class CramerShoupPrivateKeyParameters : CramerShoupKeyParameters
	{

		private BigInteger x1, x2, y1, y2, z; // Z_p
		private CramerShoupPublicKeyParameters pk; // public key

		public CramerShoupPrivateKeyParameters(CramerShoupParameters @params, BigInteger x1, BigInteger x2, BigInteger y1, BigInteger y2, BigInteger z) : base(true, @params)
		{

			this.x1 = x1;
			this.x2 = x2;
			this.y1 = y1;
			this.y2 = y2;
			this.z = z;
		}

		public virtual BigInteger getX1()
		{
			return x1;
		}

		public virtual BigInteger getX2()
		{
			return x2;
		}

		public virtual BigInteger getY1()
		{
			return y1;
		}

		public virtual BigInteger getY2()
		{
			return y2;
		}

		public virtual BigInteger getZ()
		{
			return z;
		}

		public virtual void setPk(CramerShoupPublicKeyParameters pk)
		{
			this.pk = pk;
		}

		public virtual CramerShoupPublicKeyParameters getPk()
		{
			return pk;
		}

		public override int GetHashCode()
		{
			return x1.GetHashCode() ^ x2.GetHashCode() ^ y1.GetHashCode() ^ y2.GetHashCode() ^ z.GetHashCode() ^ base.GetHashCode();
		}

		public override bool Equals(object obj)
		{
			if (!(obj is CramerShoupPrivateKeyParameters))
			{
				return false;
			}

			CramerShoupPrivateKeyParameters other = (CramerShoupPrivateKeyParameters) obj;

			return other.getX1().Equals(this.x1) && other.getX2().Equals(this.x2) && other.getY1().Equals(this.y1) && other.getY2().Equals(this.y2) && other.getZ().Equals(this.z) && base.Equals(obj);
		}
	}

}