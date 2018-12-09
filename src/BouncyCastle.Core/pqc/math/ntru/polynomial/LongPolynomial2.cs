﻿using System;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.math.ntru.polynomial
{
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A polynomial class that combines two coefficients into one <code>long</code> value for
	/// faster multiplication in 64 bit environments.<br>
	/// Coefficients can be between 0 and 2047 and are stored in pairs in the bits 0..10 and 24..34 of a <code>long</code> number.
	/// </summary>
	public class LongPolynomial2
	{
		private long[] coeffs; // each representing two coefficients in the original IntegerPolynomial
		private int numCoeffs;

		/// <summary>
		/// Constructs a <code>LongPolynomial2</code> from a <code>IntegerPolynomial</code>. The two polynomials are independent of each other.
		/// </summary>
		/// <param name="p"> the original polynomial. Coefficients must be between 0 and 2047. </param>
		public LongPolynomial2(IntegerPolynomial p)
		{
			numCoeffs = p.coeffs.Length;
			coeffs = new long[(numCoeffs + 1) / 2];
			int idx = 0;
			for (int pIdx = 0; pIdx < numCoeffs;)
			{
				int c0 = p.coeffs[pIdx++];
				while (c0 < 0)
				{
					c0 += 2048;
				}
				long c1 = pIdx < numCoeffs ? p.coeffs[pIdx++] : 0;
				while (c1 < 0)
				{
					c1 += 2048;
				}
				coeffs[idx] = c0 + (c1 << 24);
				idx++;
			}
		}

		private LongPolynomial2(long[] coeffs)
		{
			this.coeffs = coeffs;
		}

		private LongPolynomial2(int N)
		{
			coeffs = new long[N];
		}

		/// <summary>
		/// Multiplies the polynomial with another, taking the indices mod N and the values mod 2048.
		/// </summary>
		public virtual LongPolynomial2 mult(LongPolynomial2 poly2)
		{
			int N = coeffs.Length;
			if (poly2.coeffs.Length != N || numCoeffs != poly2.numCoeffs)
			{
				throw new IllegalArgumentException("Number of coefficients must be the same");
			}

			LongPolynomial2 c = multRecursive(poly2);

			if (c.coeffs.Length > N)
			{
				if (numCoeffs % 2 == 0)
				{
					for (int k = N; k < c.coeffs.Length; k++)
					{
						c.coeffs[k - N] = (c.coeffs[k - N] + c.coeffs[k]) & 0x7FF0007FFL;
					}
					c.coeffs = Arrays.copyOf(c.coeffs, N);
				}
				else
				{
					for (int k = N; k < c.coeffs.Length; k++)
					{
						c.coeffs[k - N] = c.coeffs[k - N] + (c.coeffs[k - 1] >> 24);
						c.coeffs[k - N] = c.coeffs[k - N] + ((c.coeffs[k] & 2047) << 24);
						c.coeffs[k - N] &= 0x7FF0007FFL;
					}
					c.coeffs = Arrays.copyOf(c.coeffs, N);
					c.coeffs[c.coeffs.Length - 1] &= 2047;
				}
			}

			c = new LongPolynomial2(c.coeffs);
			c.numCoeffs = numCoeffs;
			return c;
		}

		public virtual IntegerPolynomial toIntegerPolynomial()
		{
			int[] intCoeffs = new int[numCoeffs];
			int uIdx = 0;
			for (int i = 0; i < coeffs.Length; i++)
			{
				intCoeffs[uIdx++] = (int)(coeffs[i] & 2047);
				if (uIdx < numCoeffs)
				{
					intCoeffs[uIdx++] = (int)((coeffs[i] >> 24) & 2047);
				}
			}
			return new IntegerPolynomial(intCoeffs);
		}

		/// <summary>
		/// Karazuba multiplication
		/// </summary>
		private LongPolynomial2 multRecursive(LongPolynomial2 poly2)
		{
			long[] a = coeffs;
			long[] b = poly2.coeffs;

			int n = poly2.coeffs.Length;
			if (n <= 32)
			{
				int cn = 2 * n;
				LongPolynomial2 c = new LongPolynomial2(new long[cn]);
				for (int k = 0; k < cn; k++)
				{
					for (int i = Math.Max(0, k - n + 1); i <= Math.Min(k, n - 1); i++)
					{
						long c0 = a[k - i] * b[i];
						long cu = c0 & 0x7FF000000L + (c0 & 2047);
						long co = ((long)((ulong)c0 >> 48)) & 2047;

						c.coeffs[k] = (c.coeffs[k] + cu) & 0x7FF0007FFL;
						c.coeffs[k + 1] = (c.coeffs[k + 1] + co) & 0x7FF0007FFL;
					}
				}
				return c;
			}
			else
			{
				int n1 = n / 2;

				LongPolynomial2 a1 = new LongPolynomial2(Arrays.copyOf(a, n1));
				LongPolynomial2 a2 = new LongPolynomial2(Arrays.copyOfRange(a, n1, n));
				LongPolynomial2 b1 = new LongPolynomial2(Arrays.copyOf(b, n1));
				LongPolynomial2 b2 = new LongPolynomial2(Arrays.copyOfRange(b, n1, n));

				LongPolynomial2 A = (LongPolynomial2)a1.clone();
				A.add(a2);
				LongPolynomial2 B = (LongPolynomial2)b1.clone();
				B.add(b2);

				LongPolynomial2 c1 = a1.multRecursive(b1);
				LongPolynomial2 c2 = a2.multRecursive(b2);
				LongPolynomial2 c3 = A.multRecursive(B);
				c3.sub(c1);
				c3.sub(c2);

				LongPolynomial2 c = new LongPolynomial2(2 * n);
				for (int i = 0; i < c1.coeffs.Length; i++)
				{
					c.coeffs[i] = c1.coeffs[i] & 0x7FF0007FFL;
				}
				for (int i = 0; i < c3.coeffs.Length; i++)
				{
					c.coeffs[n1 + i] = (c.coeffs[n1 + i] + c3.coeffs[i]) & 0x7FF0007FFL;
				}
				for (int i = 0; i < c2.coeffs.Length; i++)
				{
					c.coeffs[2 * n1 + i] = (c.coeffs[2 * n1 + i] + c2.coeffs[i]) & 0x7FF0007FFL;
				}
				return c;
			}
		}

		/// <summary>
		/// Adds another polynomial which can have a different number of coefficients.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		private void add(LongPolynomial2 b)
		{
			if (b.coeffs.Length > coeffs.Length)
			{
				coeffs = Arrays.copyOf(coeffs, b.coeffs.Length);
			}
			for (int i = 0; i < b.coeffs.Length; i++)
			{
				coeffs[i] = (coeffs[i] + b.coeffs[i]) & 0x7FF0007FFL;
			}
		}

		/// <summary>
		/// Subtracts another polynomial which can have a different number of coefficients.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		private void sub(LongPolynomial2 b)
		{
			if (b.coeffs.Length > coeffs.Length)
			{
				coeffs = Arrays.copyOf(coeffs, b.coeffs.Length);
			}
			for (int i = 0; i < b.coeffs.Length; i++)
			{
				coeffs[i] = (0x0800000800000L + coeffs[i] - b.coeffs[i]) & 0x7FF0007FFL;
			}
		}

		/// <summary>
		/// Subtracts another polynomial which must have the same number of coefficients,
		/// and applies an AND mask to the upper and lower halves of each coefficients.
		/// </summary>
		/// <param name="b">    another polynomial </param>
		/// <param name="mask"> a bit mask less than 2048 to apply to each 11-bit coefficient </param>
		public virtual void subAnd(LongPolynomial2 b, int mask)
		{
			long longMask = (((long)mask) << 24) + mask;
			for (int i = 0; i < b.coeffs.Length; i++)
			{
				coeffs[i] = (0x0800000800000L + coeffs[i] - b.coeffs[i]) & longMask;
			}
		}

		/// <summary>
		/// Multiplies this polynomial by 2 and applies an AND mask to the upper and
		/// lower halves of each coefficients.
		/// </summary>
		/// <param name="mask"> a bit mask less than 2048 to apply to each 11-bit coefficient </param>
		public virtual void mult2And(int mask)
		{
			long longMask = (((long)mask) << 24) + mask;
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] = (coeffs[i] << 1) & longMask;
			}
		}

		public virtual object clone()
		{
			LongPolynomial2 p = new LongPolynomial2(coeffs.Clone());
			p.numCoeffs = numCoeffs;
			return p;
		}

		public override bool Equals(object obj)
		{
			if (obj is LongPolynomial2)
			{
				return Arrays.areEqual(coeffs, ((LongPolynomial2)obj).coeffs);
			}
			else
			{
				return false;
			}
		}
	}

}