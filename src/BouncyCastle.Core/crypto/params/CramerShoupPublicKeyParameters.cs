using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class CramerShoupPublicKeyParameters : CramerShoupKeyParameters
	{

		private BigInteger c, d, h; // public key group elements

		public CramerShoupPublicKeyParameters(CramerShoupParameters @params, BigInteger c, BigInteger d, BigInteger h) : base(false, @params)
		{

			this.c = c;
			this.d = d;
			this.h = h;
		}

		public virtual BigInteger getC()
		{
			return c;
		}

		public virtual BigInteger getD()
		{
			return d;
		}

		public virtual BigInteger getH()
		{
			return h;
		}

		public override int GetHashCode()
		{
			return c.GetHashCode() ^ d.GetHashCode() ^ h.GetHashCode() ^ base.GetHashCode();
		}

		public override bool Equals(object obj)
		{
			if (!(obj is CramerShoupPublicKeyParameters))
			{
				return false;
			}

			CramerShoupPublicKeyParameters other = (CramerShoupPublicKeyParameters) obj;

			return other.getC().Equals(c) && other.getD().Equals(d) && other.getH().Equals(h) && base.Equals(obj);
		}
	}

}