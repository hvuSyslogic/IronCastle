using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class ElGamalParameters : CipherParameters
	{
		private BigInteger g;
		private BigInteger p;
		private int l;

		public ElGamalParameters(BigInteger p, BigInteger g) : this(p, g, 0)
		{
		}

		public ElGamalParameters(BigInteger p, BigInteger g, int l)
		{
			this.g = g;
			this.p = p;
			this.l = l;
		}

		public virtual BigInteger getP()
		{
			return p;
		}

		/// <summary>
		/// return the generator - g
		/// </summary>
		public virtual BigInteger getG()
		{
			return g;
		}

		/// <summary>
		/// return private value limit - l
		/// </summary>
		public virtual int getL()
		{
			return l;
		}

		public override bool Equals(object obj)
		{
			if (!(obj is ElGamalParameters))
			{
				return false;
			}

			ElGamalParameters pm = (ElGamalParameters)obj;

			return pm.getP().Equals(p) && pm.getG().Equals(g) && pm.getL() == l;
		}

		public override int GetHashCode()
		{
			return (getP().GetHashCode() ^ getG().GetHashCode()) + l;
		}
	}

}