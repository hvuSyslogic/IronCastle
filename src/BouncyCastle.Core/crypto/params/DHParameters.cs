using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	public class DHParameters : CipherParameters
	{
		private const int DEFAULT_MINIMUM_LENGTH = 160;

		// not final due to compiler bug in "simpler" JDKs
		private BigInteger g;
		private BigInteger p;
		private BigInteger q;
		private BigInteger j;
		private int m;
		private int l;
		private DHValidationParameters validation;

		private static int getDefaultMParam(int lParam)
		{
			if (lParam == 0)
			{
				return DEFAULT_MINIMUM_LENGTH;
			}

			return lParam < DEFAULT_MINIMUM_LENGTH ? lParam : DEFAULT_MINIMUM_LENGTH;
		}

		public DHParameters(BigInteger p, BigInteger g) : this(p, g, null, 0)
		{
		}

		public DHParameters(BigInteger p, BigInteger g, BigInteger q) : this(p, g, q, 0)
		{
		}

		public DHParameters(BigInteger p, BigInteger g, BigInteger q, int l) : this(p, g, q, getDefaultMParam(l), l, null, null)
		{
		}

		public DHParameters(BigInteger p, BigInteger g, BigInteger q, int m, int l) : this(p, g, q, m, l, null, null)
		{
		}

		public DHParameters(BigInteger p, BigInteger g, BigInteger q, BigInteger j, DHValidationParameters validation) : this(p, g, q, DEFAULT_MINIMUM_LENGTH, 0, j, validation)
		{
		}

		public DHParameters(BigInteger p, BigInteger g, BigInteger q, int m, int l, BigInteger j, DHValidationParameters validation)
		{
			if (l != 0)
			{
				if (l > p.bitLength())
				{
					throw new IllegalArgumentException("when l value specified, it must satisfy 2^(l-1) <= p");
				}
				if (l < m)
				{
					throw new IllegalArgumentException("when l value specified, it may not be less than m value");
				}
			}

			if (m > p.bitLength())
			{
				throw new IllegalArgumentException("unsafe p value so small specific l required");
			}

			this.g = g;
			this.p = p;
			this.q = q;
			this.m = m;
			this.l = l;
			this.j = j;
			this.validation = validation;
		}

		public virtual BigInteger getP()
		{
			return p;
		}

		public virtual BigInteger getG()
		{
			return g;
		}

		public virtual BigInteger getQ()
		{
			return q;
		}

		/// <summary>
		/// Return the subgroup factor J.
		/// </summary>
		/// <returns> subgroup factor </returns>
		public virtual BigInteger getJ()
		{
			return j;
		}

		/// <summary>
		/// Return the minimum length of the private value.
		/// </summary>
		/// <returns> the minimum length of the private value in bits. </returns>
		public virtual int getM()
		{
			return m;
		}

		/// <summary>
		/// Return the private value length in bits - if set, zero otherwise
		/// </summary>
		/// <returns> the private value length in bits, zero otherwise. </returns>
		public virtual int getL()
		{
			return l;
		}

		public virtual DHValidationParameters getValidationParameters()
		{
			return validation;
		}

		public override bool Equals(object obj)
		{
			if (!(obj is DHParameters))
			{
				return false;
			}

			DHParameters pm = (DHParameters)obj;

			if (this.getQ() != null)
			{
				if (!this.getQ().Equals(pm.getQ()))
				{
					return false;
				}
			}
			else
			{
				if (pm.getQ() != null)
				{
					return false;
				}
			}

			return pm.getP().Equals(p) && pm.getG().Equals(g);
		}

		public override int GetHashCode()
		{
			return getP().GetHashCode() ^ getG().GetHashCode() ^ (getQ() != null ? getQ().GetHashCode() : 0);
		}
	}

}