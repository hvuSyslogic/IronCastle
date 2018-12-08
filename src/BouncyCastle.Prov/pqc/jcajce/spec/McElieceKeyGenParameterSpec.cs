namespace org.bouncycastle.pqc.jcajce.spec
{

	using PolynomialRingGF2 = org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2;

	/// <summary>
	/// This class provides a specification for the parameters that are used by the
	/// McEliece, McElieceCCA2, and Niederreiter key pair generators.
	/// </summary>
	public class McElieceKeyGenParameterSpec : AlgorithmParameterSpec
	{

		/// <summary>
		/// The default extension degree
		/// </summary>
		public const int DEFAULT_M = 11;

		/// <summary>
		/// The default error correcting capability.
		/// </summary>
		public const int DEFAULT_T = 50;

		/// <summary>
		/// extension degree of the finite field GF(2^m)
		/// </summary>
		private int m;

		/// <summary>
		/// error correction capability of the code
		/// </summary>
		private int t;

		/// <summary>
		/// length of the code
		/// </summary>
		private int n;

		/// <summary>
		/// the field polynomial
		/// </summary>
		private int fieldPoly;

		/// <summary>
		/// Constructor. Set the default parameters: extension degree.
		/// </summary>
		public McElieceKeyGenParameterSpec() : this(DEFAULT_M, DEFAULT_T)
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="keysize"> the length of a Goppa code </param>
		/// <exception cref="IllegalArgumentException"> if <tt>keysize &lt; 1</tt>. </exception>
		public McElieceKeyGenParameterSpec(int keysize)
		{
			if (keysize < 1)
			{
				throw new IllegalArgumentException("key size must be positive");
			}
			m = 0;
			n = 1;
			while (n < keysize)
			{
				n <<= 1;
				m++;
			}
			t = (int)((uint)n >> 1);
			t /= m;
			fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m);
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="m"> degree of the finite field GF(2^m) </param>
		/// <param name="t"> error correction capability of the code </param>
		/// <exception cref="InvalidParameterException"> if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
		/// <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>. </exception>
		public McElieceKeyGenParameterSpec(int m, int t)
		{
			if (m < 1)
			{
				throw new IllegalArgumentException("m must be positive");
			}
			if (m > 32)
			{
				throw new IllegalArgumentException("m is too large");
			}
			this.m = m;
			n = 1 << m;
			if (t < 0)
			{
				throw new IllegalArgumentException("t must be positive");
			}
			if (t > n)
			{
				throw new IllegalArgumentException("t must be less than n = 2^m");
			}
			this.t = t;
			fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m);
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="m">    degree of the finite field GF(2^m) </param>
		/// <param name="t">    error correction capability of the code </param>
		/// <param name="poly"> the field polynomial </param>
		/// <exception cref="IllegalArgumentException"> if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
		/// <tt>t &lt; 0</tt> or <tt>t &gt; n</tt> or
		/// <tt>poly</tt> is not an irreducible field polynomial. </exception>
		public McElieceKeyGenParameterSpec(int m, int t, int poly)
		{
			this.m = m;
			if (m < 1)
			{
				throw new IllegalArgumentException("m must be positive");
			}
			if (m > 32)
			{
				throw new IllegalArgumentException(" m is too large");
			}
			this.n = 1 << m;
			this.t = t;
			if (t < 0)
			{
				throw new IllegalArgumentException("t must be positive");
			}
			if (t > n)
			{
				throw new IllegalArgumentException("t must be less than n = 2^m");
			}
			if ((PolynomialRingGF2.degree(poly) == m) && (PolynomialRingGF2.isIrreducible(poly)))
			{
				this.fieldPoly = poly;
			}
			else
			{
				throw new IllegalArgumentException("polynomial is not a field polynomial for GF(2^m)");
			}
		}

		/// <returns> the extension degree of the finite field GF(2^m) </returns>
		public virtual int getM()
		{
			return m;
		}

		/// <returns> the length of the code </returns>
		public virtual int getN()
		{
			return n;
		}

		/// <returns> the error correction capability of the code </returns>
		public virtual int getT()
		{
			return t;
		}

		/// <returns> the field polynomial </returns>
		public virtual int getFieldPoly()
		{
			return fieldPoly;
		}

	}

}