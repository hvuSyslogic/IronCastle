using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.pqc.math.ntru.util;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.math.ntru.polynomial
{

			
	/// <summary>
	/// A <code>TernaryPolynomial</code> with a "low" number of nonzero coefficients.
	/// </summary>
	public class SparseTernaryPolynomial : TernaryPolynomial
	{
		/// <summary>
		/// Number of bits to use for each coefficient. Determines the upper bound for <code>N</code>.
		/// </summary>
		private const int BITS_PER_INDEX = 11;

		private int N;
		private int[] ones;
		private int[] negOnes;

		/// <summary>
		/// Constructs a new polynomial.
		/// </summary>
		/// <param name="N">       total number of coefficients including zeros </param>
		/// <param name="ones">    indices of coefficients equal to 1 </param>
		/// <param name="negOnes"> indices of coefficients equal to -1 </param>
		public SparseTernaryPolynomial(int N, int[] ones, int[] negOnes)
		{
			this.N = N;
			this.ones = ones;
			this.negOnes = negOnes;
		}

		/// <summary>
		/// Constructs a <code>DenseTernaryPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
		/// independent of each other.
		/// </summary>
		/// <param name="intPoly"> the original polynomial </param>
		public SparseTernaryPolynomial(IntegerPolynomial intPoly) : this(intPoly.coeffs)
		{
		}

		/// <summary>
		/// Constructs a new <code>SparseTernaryPolynomial</code> with a given set of coefficients.
		/// </summary>
		/// <param name="coeffs"> the coefficients </param>
		public SparseTernaryPolynomial(int[] coeffs)
		{
			N = coeffs.Length;
			ones = new int[N];
			negOnes = new int[N];
			int onesIdx = 0;
			int negOnesIdx = 0;
			for (int i = 0; i < N; i++)
			{
				int c = coeffs[i];
				switch (c)
				{
				case 1:
					ones[onesIdx++] = i;
					break;
				case -1:
					negOnes[negOnesIdx++] = i;
					break;
				case 0:
					break;
				default:
					throw new IllegalArgumentException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
				}
			}
			ones = Arrays.copyOf(ones, onesIdx);
			negOnes = Arrays.copyOf(negOnes, negOnesIdx);
		}

		/// <summary>
		/// Decodes a byte array encoded with <seealso cref="#toBinary()"/> to a ploynomial.
		/// </summary>
		/// <param name="is">         an input stream containing an encoded polynomial </param>
		/// <param name="N">          number of coefficients including zeros </param>
		/// <param name="numOnes">    number of coefficients equal to 1 </param>
		/// <param name="numNegOnes"> number of coefficients equal to -1 </param>
		/// <returns> the decoded polynomial </returns>
		/// <exception cref="IOException"> </exception>
		public static SparseTernaryPolynomial fromBinary(InputStream @is, int N, int numOnes, int numNegOnes)
		{
			int maxIndex = 1 << BITS_PER_INDEX;
			int bitsPerIndex = 32 - Integer.numberOfLeadingZeros(maxIndex - 1);

			int data1Len = (numOnes * bitsPerIndex + 7) / 8;
			byte[] data1 = Util.readFullLength(@is, data1Len);
			int[] ones = ArrayEncoder.decodeModQ(data1, numOnes, maxIndex);

			int data2Len = (numNegOnes * bitsPerIndex + 7) / 8;
			byte[] data2 = Util.readFullLength(@is, data2Len);
			int[] negOnes = ArrayEncoder.decodeModQ(data2, numNegOnes, maxIndex);

			return new SparseTernaryPolynomial(N, ones, negOnes);
		}

		/// <summary>
		/// Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
		/// <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
		/// </summary>
		/// <param name="N">          number of coefficients </param>
		/// <param name="numOnes">    number of 1's </param>
		/// <param name="numNegOnes"> number of -1's </param>
		public static SparseTernaryPolynomial generateRandom(int N, int numOnes, int numNegOnes, SecureRandom random)
		{
			int[] coeffs = Util.generateRandomTernary(N, numOnes, numNegOnes, random);
			return new SparseTernaryPolynomial(coeffs);
		}

		public virtual IntegerPolynomial mult(IntegerPolynomial poly2)
		{
			int[] b = poly2.coeffs;
			if (b.Length != N)
			{
				throw new IllegalArgumentException("Number of coefficients must be the same");
			}

			int[] c = new int[N];
			for (int idx = 0; idx != ones.Length; idx++)
			{
				int i = ones[idx];
				int j = N - 1 - i;
				for (int k = N - 1; k >= 0; k--)
				{
					c[k] += b[j];
					j--;
					if (j < 0)
					{
						j = N - 1;
					}
				}
			}

			for (int idx = 0; idx != negOnes.Length; idx++)
			{
				int i = negOnes[idx];
				int j = N - 1 - i;
				for (int k = N - 1; k >= 0; k--)
				{
					c[k] -= b[j];
					j--;
					if (j < 0)
					{
						j = N - 1;
					}
				}
			}

			return new IntegerPolynomial(c);
		}

		public virtual IntegerPolynomial mult(IntegerPolynomial poly2, int modulus)
		{
			IntegerPolynomial c = mult(poly2);
			c.mod(modulus);
			return c;
		}

		public virtual BigIntPolynomial mult(BigIntPolynomial poly2)
		{
			BigInteger[] b = poly2.coeffs;
			if (b.Length != N)
			{
				throw new IllegalArgumentException("Number of coefficients must be the same");
			}

			BigInteger[] c = new BigInteger[N];
			for (int i = 0; i < N; i++)
			{
				c[i] = BigInteger.ZERO;
			}

			for (int idx = 0; idx != ones.Length; idx++)
			{
				int i = ones[idx];
				int j = N - 1 - i;
				for (int k = N - 1; k >= 0; k--)
				{
					c[k] = c[k].add(b[j]);
					j--;
					if (j < 0)
					{
						j = N - 1;
					}
				}
			}

			for (int idx = 0; idx != negOnes.Length; idx++)
			{
				int i = negOnes[idx];
				int j = N - 1 - i;
				for (int k = N - 1; k >= 0; k--)
				{
					c[k] = c[k].subtract(b[j]);
					j--;
					if (j < 0)
					{
						j = N - 1;
					}
				}
			}

			return new BigIntPolynomial(c);
		}

		public virtual int[] getOnes()
		{
			return ones;
		}

		public virtual int[] getNegOnes()
		{
			return negOnes;
		}

		/// <summary>
		/// Encodes the polynomial to a byte array writing <code>BITS_PER_INDEX</code> bits for each coefficient.
		/// </summary>
		/// <returns> the encoded polynomial </returns>
		public virtual byte[] toBinary()
		{
			int maxIndex = 1 << BITS_PER_INDEX;
			byte[] bin1 = ArrayEncoder.encodeModQ(ones, maxIndex);
			byte[] bin2 = ArrayEncoder.encodeModQ(negOnes, maxIndex);

			byte[] bin = Arrays.copyOf(bin1, bin1.Length + bin2.Length);
			JavaSystem.arraycopy(bin2, 0, bin, bin1.Length, bin2.Length);
			return bin;
		}

		public virtual IntegerPolynomial toIntegerPolynomial()
		{
			int[] coeffs = new int[N];
			for (int idx = 0; idx != ones.Length; idx++)
			{
				int i = ones[idx];
				coeffs[i] = 1;
			}
			for (int idx = 0; idx != negOnes.Length; idx++)
			{
				int i = negOnes[idx];
				coeffs[i] = -1;
			}
			return new IntegerPolynomial(coeffs);
		}

		public virtual int size()
		{
			return N;
		}

		public virtual void clear()
		{
			for (int i = 0; i < ones.Length; i++)
			{
				ones[i] = 0;
			}
			for (int i = 0; i < negOnes.Length; i++)
			{
				negOnes[i] = 0;
			}
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + N;
			result = prime * result + Arrays.GetHashCode(negOnes);
			result = prime * result + Arrays.GetHashCode(ones);
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
			SparseTernaryPolynomial other = (SparseTernaryPolynomial)obj;
			if (N != other.N)
			{
				return false;
			}
			if (!Arrays.areEqual(negOnes, other.negOnes))
			{
				return false;
			}
			if (!Arrays.areEqual(ones, other.ones))
			{
				return false;
			}
			return true;
		}
	}

}