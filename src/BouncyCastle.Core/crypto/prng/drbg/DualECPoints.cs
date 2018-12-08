using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.prng.drbg
{
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// General class for providing point pairs for use with DualEC DRBG. See NIST SP 800-90A for further details.
	/// </summary>
	public class DualECPoints
	{
		private readonly ECPoint p;
		private readonly ECPoint q;
		private readonly int securityStrength;
		private readonly int cofactor;

		/// <summary>
		/// Base Constructor.
		/// <para>
		/// The cofactor is used to calculate the output block length (maxOutlen) according to
		/// <pre>
		///     max_outlen = largest multiple of 8 less than ((field size in bits) - (13 + log2(cofactor))
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <param name="securityStrength"> maximum security strength to be associated with these parameters </param>
		/// <param name="p"> the P point. </param>
		/// <param name="q"> the Q point. </param>
		/// <param name="cofactor"> cofactor associated with the domain parameters for the point generation. </param>
		public DualECPoints(int securityStrength, ECPoint p, ECPoint q, int cofactor)
		{
			if (!p.getCurve().Equals(q.getCurve()))
			{
				throw new IllegalArgumentException("points need to be on the same curve");
			}

			this.securityStrength = securityStrength;
			this.p = p;
			this.q = q;
			this.cofactor = cofactor;
		}

		public virtual int getSeedLen()
		{
			return p.getCurve().getFieldSize();
		}

		public virtual int getMaxOutlen()
		{
			return ((p.getCurve().getFieldSize() - (13 + log2(cofactor))) / 8) * 8;
		}

		public virtual ECPoint getP()
		{
			return p;
		}

		public virtual ECPoint getQ()
		{
			return q;
		}

		public virtual int getSecurityStrength()
		{
			return securityStrength;
		}

		public virtual int getCofactor()
		{
			return cofactor;
		}

		private static int log2(int value)
		{
			int log = 0;

			while ((value >>= 1) != 0)
			{
				log++;
			}

			return log;
		}
	}

}