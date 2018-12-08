using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.math.ntru.polynomial
{

	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A polynomial with <seealso cref="BigInteger"/> coefficients.<br>
	/// Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
	/// not but return the result as a new polynomial.
	/// </summary>
	public class BigIntPolynomial
	{
		private static readonly double LOG_10_2 = Math.log10(2);

		internal BigInteger[] coeffs;

		/// <summary>
		/// Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
		/// </summary>
		/// <param name="N"> the number of coefficients </param>
		public BigIntPolynomial(int N)
		{
			coeffs = new BigInteger[N];
			for (int i = 0; i < N; i++)
			{
				coeffs[i] = Constants.BIGINT_ZERO;
			}
		}

		/// <summary>
		/// Constructs a new polynomial with a given set of coefficients.
		/// </summary>
		/// <param name="coeffs"> the coefficients </param>
		public BigIntPolynomial(BigInteger[] coeffs)
		{
			this.coeffs = coeffs;
		}

		/// <summary>
		/// Constructs a <code>BigIntPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
		/// independent of each other.
		/// </summary>
		/// <param name="p"> the original polynomial </param>
		public BigIntPolynomial(IntegerPolynomial p)
		{
			coeffs = new BigInteger[p.coeffs.Length];
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] = BigInteger.valueOf(p.coeffs[i]);
			}
		}

		/// <summary>
		/// Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
		/// <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
		/// </summary>
		/// <param name="N">          number of coefficients </param>
		/// <param name="numOnes">    number of 1's </param>
		/// <param name="numNegOnes"> number of -1's </param>
		/// <returns> a random polynomial. </returns>
		internal static BigIntPolynomial generateRandomSmall(int N, int numOnes, int numNegOnes)
		{
			List coeffs = new ArrayList();
			for (int i = 0; i < numOnes; i++)
			{
				coeffs.add(Constants.BIGINT_ONE);
			}
			for (int i = 0; i < numNegOnes; i++)
			{
				coeffs.add(BigInteger.valueOf(-1));
			}
			while (coeffs.size() < N)
			{
				coeffs.add(Constants.BIGINT_ZERO);
			}
			Collections.shuffle(coeffs, CryptoServicesRegistrar.getSecureRandom());

			BigIntPolynomial poly = new BigIntPolynomial(N);
			for (int i = 0; i < coeffs.size(); i++)
			{
				poly.coeffs[i] = (BigInteger)coeffs.get(i);
			}
			return poly;
		}

		/// <summary>
		/// Multiplies the polynomial by another, taking the indices mod N. Does not
		/// change this polynomial but returns the result as a new polynomial.<br>
		/// Both polynomials must have the same number of coefficients.
		/// </summary>
		/// <param name="poly2"> the polynomial to multiply by </param>
		/// <returns> a new polynomial </returns>
		public virtual BigIntPolynomial mult(BigIntPolynomial poly2)
		{
			int N = coeffs.Length;
			if (poly2.coeffs.Length != N)
			{
				throw new IllegalArgumentException("Number of coefficients must be the same");
			}

			BigIntPolynomial c = multRecursive(poly2);

			if (c.coeffs.Length > N)
			{
				for (int k = N; k < c.coeffs.Length; k++)
				{
					c.coeffs[k - N] = c.coeffs[k - N].add(c.coeffs[k]);
				}
				c.coeffs = Arrays.copyOf(c.coeffs, N);
			}
			return c;
		}

		/// <summary>
		/// Karazuba multiplication
		/// </summary>
		private BigIntPolynomial multRecursive(BigIntPolynomial poly2)
		{
			BigInteger[] a = coeffs;
			BigInteger[] b = poly2.coeffs;

			int n = poly2.coeffs.Length;
			if (n <= 1)
			{
				BigInteger[] c = Arrays.clone(coeffs);
				for (int i = 0; i < coeffs.Length; i++)
				{
					c[i] = c[i].multiply(poly2.coeffs[0]);
				}
				return new BigIntPolynomial(c);
			}
			else
			{
				int n1 = n / 2;

				BigIntPolynomial a1 = new BigIntPolynomial(Arrays.copyOf(a, n1));
				BigIntPolynomial a2 = new BigIntPolynomial(Arrays.copyOfRange(a, n1, n));
				BigIntPolynomial b1 = new BigIntPolynomial(Arrays.copyOf(b, n1));
				BigIntPolynomial b2 = new BigIntPolynomial(Arrays.copyOfRange(b, n1, n));

				BigIntPolynomial A = (BigIntPolynomial)a1.clone();
				A.add(a2);
				BigIntPolynomial B = (BigIntPolynomial)b1.clone();
				B.add(b2);

				BigIntPolynomial c1 = a1.multRecursive(b1);
				BigIntPolynomial c2 = a2.multRecursive(b2);
				BigIntPolynomial c3 = A.multRecursive(B);
				c3.sub(c1);
				c3.sub(c2);

				BigIntPolynomial c = new BigIntPolynomial(2 * n - 1);
				for (int i = 0; i < c1.coeffs.Length; i++)
				{
					c.coeffs[i] = c1.coeffs[i];
				}
				for (int i = 0; i < c3.coeffs.Length; i++)
				{
					c.coeffs[n1 + i] = c.coeffs[n1 + i].add(c3.coeffs[i]);
				}
				for (int i = 0; i < c2.coeffs.Length; i++)
				{
					c.coeffs[2 * n1 + i] = c.coeffs[2 * n1 + i].add(c2.coeffs[i]);
				}
				return c;
			}
		}

		/// <summary>
		/// Adds another polynomial which can have a different number of coefficients,
		/// and takes the coefficient values mod <code>modulus</code>.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		public virtual void add(BigIntPolynomial b, BigInteger modulus)
		{
			add(b);
			mod(modulus);
		}

		/// <summary>
		/// Adds another polynomial which can have a different number of coefficients.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		public virtual void add(BigIntPolynomial b)
		{
			if (b.coeffs.Length > coeffs.Length)
			{
				int N = coeffs.Length;
				coeffs = Arrays.copyOf(coeffs, b.coeffs.Length);
				for (int i = N; i < coeffs.Length; i++)
				{
					coeffs[i] = Constants.BIGINT_ZERO;
				}
			}
			for (int i = 0; i < b.coeffs.Length; i++)
			{
				coeffs[i] = coeffs[i].add(b.coeffs[i]);
			}
		}

		/// <summary>
		/// Subtracts another polynomial which can have a different number of coefficients.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		public virtual void sub(BigIntPolynomial b)
		{
			if (b.coeffs.Length > coeffs.Length)
			{
				int N = coeffs.Length;
				coeffs = Arrays.copyOf(coeffs, b.coeffs.Length);
				for (int i = N; i < coeffs.Length; i++)
				{
					coeffs[i] = Constants.BIGINT_ZERO;
				}
			}
			for (int i = 0; i < b.coeffs.Length; i++)
			{
				coeffs[i] = coeffs[i].subtract(b.coeffs[i]);
			}
		}

		/// <summary>
		/// Multiplies each coefficient by a <code>BigInteger</code>. Does not return a new polynomial but modifies this polynomial.
		/// </summary>
		/// <param name="factor"> </param>
		public virtual void mult(BigInteger factor)
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] = coeffs[i].multiply(factor);
			}
		}

		/// <summary>
		/// Multiplies each coefficient by a <code>int</code>. Does not return a new polynomial but modifies this polynomial.
		/// </summary>
		/// <param name="factor"> </param>
		public virtual void mult(int factor)
		{
			mult(BigInteger.valueOf(factor));
		}

		/// <summary>
		/// Divides each coefficient by a <code>BigInteger</code> and rounds the result to the nearest whole number.<br>
		/// Does not return a new polynomial but modifies this polynomial.
		/// </summary>
		/// <param name="divisor"> the number to divide by </param>
		public virtual void div(BigInteger divisor)
		{
			BigInteger d = divisor.add(Constants.BIGINT_ONE).divide(BigInteger.valueOf(2));
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] = coeffs[i].compareTo(Constants.BIGINT_ZERO) > 0 ? coeffs[i].add(d) : coeffs[i].add(d.negate());
				coeffs[i] = coeffs[i].divide(divisor);
			}
		}

		/// <summary>
		/// Divides each coefficient by a <code>BigDecimal</code> and rounds the result to <code>decimalPlaces</code> places.
		/// </summary>
		/// <param name="divisor">       the number to divide by </param>
		/// <param name="decimalPlaces"> the number of fractional digits to round the result to </param>
		/// <returns> a new <code>BigDecimalPolynomial</code> </returns>
		public virtual BigDecimalPolynomial div(BigDecimal divisor, int decimalPlaces)
		{
			BigInteger max = maxCoeffAbs();
			int coeffLength = (int)(max.bitLength() * LOG_10_2) + 1;
			// factor = 1/divisor
			BigDecimal factor = Constants.BIGDEC_ONE.divide(divisor, coeffLength + decimalPlaces + 1, BigDecimal.ROUND_HALF_EVEN);

			// multiply each coefficient by factor
			BigDecimalPolynomial p = new BigDecimalPolynomial(coeffs.Length);
			for (int i = 0; i < coeffs.Length; i++)
			{
			// multiply, then truncate after decimalPlaces so subsequent operations aren't slowed down
				p.coeffs[i] = (new BigDecimal(coeffs[i])).multiply(factor).setScale(decimalPlaces, BigDecimal.ROUND_HALF_EVEN);
			}

			return p;
		}

		/// <summary>
		/// Returns the base10 length of the largest coefficient.
		/// </summary>
		/// <returns> length of the longest coefficient </returns>
		public virtual int getMaxCoeffLength()
		{
			return (int)(maxCoeffAbs().bitLength() * LOG_10_2) + 1;
		}

		private BigInteger maxCoeffAbs()
		{
			BigInteger max = coeffs[0].abs();
			for (int i = 1; i < coeffs.Length; i++)
			{
				BigInteger coeff = coeffs[i].abs();
				if (coeff.compareTo(max) > 0)
				{
					max = coeff;
				}
			}
			return max;
		}

		/// <summary>
		/// Takes each coefficient modulo a number.
		/// </summary>
		/// <param name="modulus"> </param>
		public virtual void mod(BigInteger modulus)
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] = coeffs[i].mod(modulus);
			}
		}

		/// <summary>
		/// Returns the sum of all coefficients, i.e. evaluates the polynomial at 0.
		/// </summary>
		/// <returns> the sum of all coefficients </returns>
		public virtual BigInteger sumCoeffs()
		{
			BigInteger sum = Constants.BIGINT_ZERO;
			for (int i = 0; i < coeffs.Length; i++)
			{
				sum = sum.add(coeffs[i]);
			}
			return sum;
		}

		/// <summary>
		/// Makes a copy of the polynomial that is independent of the original.
		/// </summary>
		public virtual object clone()
		{
			return new BigIntPolynomial(coeffs.Clone());
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + Arrays.GetHashCode(coeffs);
			return result;
		}

		public override bool Equals(object obj)
		{
			if (this == obj)
			{
				return true;
			}
			if (obj == null)
			{
				return false;
			}
			if (this.GetType() != obj.GetType())
			{
				return false;
			}
			BigIntPolynomial other = (BigIntPolynomial)obj;
			if (!Arrays.areEqual(coeffs, other.coeffs))
			{
				return false;
			}
			return true;
		}

		public virtual BigInteger[] getCoeffs()
		{
			return Arrays.clone(coeffs);
		}
	}

}