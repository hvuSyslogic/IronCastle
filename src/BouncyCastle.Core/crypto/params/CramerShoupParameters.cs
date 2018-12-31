using BouncyCastle.Core.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.@params
{

	
	public class CramerShoupParameters : CipherParameters
	{

		private BigInteger p; // prime order of G
		private BigInteger g1, g2; // generate G

		private Digest H; // hash function

		public CramerShoupParameters(BigInteger p, BigInteger g1, BigInteger g2, Digest H)
		{
			this.p = p;
			this.g1 = g1;
			this.g2 = g2;
			this.H = (Digest)((Memoable)H).copy();
			this.H.reset();
		}

		public override bool Equals(object obj)
		{
			if (!(obj is CramerShoupParameters))
			{
				return false;
			}

			CramerShoupParameters pm = (CramerShoupParameters)obj;

			return (pm.getP().Equals(p) && pm.getG1().Equals(g1) && pm.getG2().Equals(g2));
		}

		public override int GetHashCode()
		{
			return getP().GetHashCode() ^ getG1().GetHashCode() ^ getG2().GetHashCode();
		}

		public virtual BigInteger getG1()
		{
			return g1;
		}

		public virtual BigInteger getG2()
		{
			return g2;
		}

		public virtual BigInteger getP()
		{
			return p;
		}

		public virtual Digest getH()
		{
			return (Digest)((Memoable)H).copy();
		}

	}

}