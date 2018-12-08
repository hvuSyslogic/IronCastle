using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.pqc.crypto.ntru
{

	using DenseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
	using IntegerPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
	using Polynomial = org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
	using ProductFormPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.ProductFormPolynomial;
	using SparseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;

	/// <summary>
	/// A NtruEncrypt private key is essentially a polynomial named <code>f</code>
	/// which takes different forms depending on whether product-form polynomials are used,
	/// and on <code>fastP</code><br>
	/// The inverse of <code>f</code> modulo <code>p</code> is precomputed on initialization.
	/// </summary>
	public class NTRUEncryptionPrivateKeyParameters : NTRUEncryptionKeyParameters
	{
		public Polynomial t;
		public IntegerPolynomial fp;
		public IntegerPolynomial h;

		/// <summary>
		/// Constructs a new private key from a polynomial
		/// </summary>
		/// <param name="h"> the public polynomial for the key. </param>
		/// <param name="t">      the polynomial which determines the key: if <code>fastFp=true</code>, <code>f=1+3t</code>; otherwise, <code>f=t</code> </param>
		/// <param name="fp">     the inverse of <code>f</code> </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		public NTRUEncryptionPrivateKeyParameters(IntegerPolynomial h, Polynomial t, IntegerPolynomial fp, NTRUEncryptionParameters @params) : base(true, @params)
		{

			this.h = h;
			this.t = t;
			this.fp = fp;
		}

		/// <summary>
		/// Converts a byte array to a polynomial <code>f</code> and constructs a new private key
		/// </summary>
		/// <param name="b">      an encoded polynomial </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		/// <seealso cref= #getEncoded() </seealso>
		public NTRUEncryptionPrivateKeyParameters(byte[] b, NTRUEncryptionParameters @params) : this(new ByteArrayInputStream(b), @params)
		{
		}

		/// <summary>
		/// Reads a polynomial <code>f</code> from an input stream and constructs a new private key
		/// </summary>
		/// <param name="is">     an input stream </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		/// <seealso cref= #writeTo(OutputStream) </seealso>
		public NTRUEncryptionPrivateKeyParameters(InputStream @is, NTRUEncryptionParameters @params) : base(true, @params)
		{

			if (@params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT)
			{
				int N = @params.N;
				int df1 = @params.df1;
				int df2 = @params.df2;
				int df3Ones = @params.df3;
				int df3NegOnes = @params.fastFp ? @params.df3 : @params.df3 - 1;
				h = IntegerPolynomial.fromBinary(@is, @params.N, @params.q);
				t = ProductFormPolynomial.fromBinary(@is, N, df1, df2, df3Ones, df3NegOnes);
			}
			else
			{
				h = IntegerPolynomial.fromBinary(@is, @params.N, @params.q);
				IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Tight(@is, @params.N);
				t = @params.sparse ? new SparseTernaryPolynomial(fInt) : new DenseTernaryPolynomial(fInt);
			}

			init();
		}

		/// <summary>
		/// Initializes <code>fp</code> from t.
		/// </summary>
		private void init()
		{
			if (@params.fastFp)
			{
				fp = new IntegerPolynomial(@params.N);
				fp.coeffs[0] = 1;
			}
			else
			{
				fp = t.toIntegerPolynomial().invertF3();
			}
		}

		/// <summary>
		/// Converts the key to a byte array
		/// </summary>
		/// <returns> the encoded key </returns>
		/// <seealso cref= #NTRUEncryptionPrivateKeyParameters(byte[], NTRUEncryptionParameters) </seealso>
		public virtual byte[] getEncoded()
		{
			byte[] hBytes = h.toBinary(@params.q);
			byte[] tBytes;

			if (t is ProductFormPolynomial)
			{
				tBytes = ((ProductFormPolynomial)t).toBinary();
			}
			else
			{
				tBytes = t.toIntegerPolynomial().toBinary3Tight();
			}

			byte[] res = new byte[hBytes.Length + tBytes.Length];

			JavaSystem.arraycopy(hBytes, 0, res, 0, hBytes.Length);
			JavaSystem.arraycopy(tBytes, 0, res, hBytes.Length, tBytes.Length);

			return res;
		}

		/// <summary>
		/// Writes the key to an output stream
		/// </summary>
		/// <param name="os"> an output stream </param>
		/// <exception cref="IOException"> </exception>
		/// <seealso cref= #NTRUEncryptionPrivateKeyParameters(InputStream, NTRUEncryptionParameters) </seealso>
		public virtual void writeTo(OutputStream os)
		{
			os.write(getEncoded());
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + ((@params == null) ? 0 : @params.GetHashCode());
			result = prime * result + ((t == null) ? 0 : t.GetHashCode());
			result = prime * result + ((h == null) ? 0 : h.GetHashCode());
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
			if (!(obj is NTRUEncryptionPrivateKeyParameters))
			{
				return false;
			}
			NTRUEncryptionPrivateKeyParameters other = (NTRUEncryptionPrivateKeyParameters)obj;
			if (@params == null)
			{
				if (other.@params != null)
				{
					return false;
				}
			}
			else if (!@params.Equals(other.@params))
			{
				return false;
			}
			if (t == null)
			{
				if (other.t != null)
				{
					return false;
				}
			}
			else if (!t.Equals(other.t))
			{
				return false;
			}
			if (!h.Equals(other.h))
			{
				return false;
			}
			return true;
		}
	}
}