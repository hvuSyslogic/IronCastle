using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.@params
{

					
	public class ECDomainParameters : ECConstants
	{
		private ECCurve curve;
		private byte[] seed;
		private ECPoint G;
		private BigInteger n;
		private BigInteger h;
		private BigInteger hInv = null;

		public ECDomainParameters(ECCurve curve, ECPoint G, BigInteger n) : this(curve, G, n, org.bouncycastle.math.ec.ECConstants_Fields.ONE, null)
		{
		}

		public ECDomainParameters(ECCurve curve, ECPoint G, BigInteger n, BigInteger h) : this(curve, G, n, h, null)
		{
		}

		public ECDomainParameters(ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed)
		{
			if (curve == null)
			{
				throw new NullPointerException("curve");
			}
			if (n == null)
			{
				throw new NullPointerException("n");
			}
			// we can't check for h == null here as h is optional in X9.62 as it is not required for ECDSA

			this.curve = curve;
			this.G = validate(curve, G);
			this.n = n;
			this.h = h;
			this.seed = Arrays.clone(seed);
		}

		public virtual ECCurve getCurve()
		{
			return curve;
		}

		public virtual ECPoint getG()
		{
			return G;
		}

		public virtual BigInteger getN()
		{
			return n;
		}

		public virtual BigInteger getH()
		{
			return h;
		}

		public virtual BigInteger getHInv()
		{
			lock (this)
			{
				if (hInv == null)
				{
					hInv = h.modInverse(n);
				}
				return hInv;
			}
		}

		public virtual byte[] getSeed()
		{
			return Arrays.clone(seed);
		}

		public override bool Equals(object obj)
		{
			if (this == obj)
			{
				return true;
			}

			if ((obj is ECDomainParameters))
			{
				ECDomainParameters other = (ECDomainParameters)obj;

				return this.curve.Equals(other.curve) && this.G.Equals(other.G) && this.n.Equals(other.n) && this.h.Equals(other.h);
			}

			return false;
		}

		public override int GetHashCode()
		{
			int hc = curve.GetHashCode();
			hc *= 37;
			hc ^= G.GetHashCode();
			hc *= 37;
			hc ^= n.GetHashCode();
			hc *= 37;
			hc ^= h.GetHashCode();
			return hc;
		}

		internal static ECPoint validate(ECCurve c, ECPoint q)
		{
			if (q == null)
			{
				throw new IllegalArgumentException("Point has null value");
			}

			q = ECAlgorithms.importPoint(c, q).normalize();

			if (q.isInfinity())
			{
				throw new IllegalArgumentException("Point at infinity");
			}

			if (!q.isValid())
			{
				throw new IllegalArgumentException("Point not on curve");
			}

			return q;
		}
	}

}