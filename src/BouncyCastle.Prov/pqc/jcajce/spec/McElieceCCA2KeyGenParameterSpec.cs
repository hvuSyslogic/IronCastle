namespace org.bouncycastle.pqc.jcajce.spec
{

	using PolynomialRingGF2 = org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2;

	/// <summary>
	/// This class provides a specification for the parameters that are used by the
	/// McEliece, McElieceCCA2, and Niederreiter key pair generators.
	/// </summary>
	public class McElieceCCA2KeyGenParameterSpec : AlgorithmParameterSpec
	{
		public const string SHA1 = "SHA-1";
		public const string SHA224 = "SHA-224";
		public const string SHA256 = "SHA-256";
		public const string SHA384 = "SHA-384";
		public const string SHA512 = "SHA-512";

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
		private readonly int m;

		/// <summary>
		/// error correction capability of the code
		/// </summary>
		private readonly int t;

		/// <summary>
		/// length of the code
		/// </summary>
		private readonly int n;

		/// <summary>
		/// the field polynomial
		/// </summary>
		private int fieldPoly;

		private readonly string digest;

		/// <summary>
		/// Constructor. Set the default parameters: extension degree.
		/// </summary>
		public McElieceCCA2KeyGenParameterSpec() : this(DEFAULT_M, DEFAULT_T, SHA256)
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="keysize"> the length of a Goppa code </param>
		/// <exception cref="IllegalArgumentException"> if <tt>keysize &lt; 1</tt>. </exception>
		public McElieceCCA2KeyGenParameterSpec(int keysize) : this(keysize, SHA256)
		{
		}

		public McElieceCCA2KeyGenParameterSpec(int keysize, string digest)
		{
			if (keysize < 1)
			{
				throw new IllegalArgumentException("key size must be positive");
			}
			int m = 0;
			int n = 1;
			while (n < keysize)
			{
				n <<= 1;
				m++;
			}
			t = ((int)((uint)n >> 1)) / m;

			this.m = m;
			this.n = n;
			this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m);
			this.digest = digest;
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="m"> degree of the finite field GF(2^m) </param>
		/// <param name="t"> error correction capability of the code </param>
		/// <exception cref="InvalidParameterException"> if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
		/// <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>. </exception>
		public McElieceCCA2KeyGenParameterSpec(int m, int t) : this(m, t, SHA256)
		{
		}

		public McElieceCCA2KeyGenParameterSpec(int m, int t, string digest)
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
			this.digest = digest;
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
		public McElieceCCA2KeyGenParameterSpec(int m, int t, int poly) : this(m, t, poly, SHA256)
		{
		}

		public McElieceCCA2KeyGenParameterSpec(int m, int t, int poly, string digest)
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
			this.digest = digest;
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

		/// <summary>
		/// Return CCA-2 digest.
		/// </summary>
		public virtual string getDigest()
		{
			return digest;
		}
	}

}