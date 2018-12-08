using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.pqc.crypto.ntru
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using IntegerPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;

	/// <summary>
	/// A NtruSign public key is essentially a polynomial named <code>h</code>.
	/// </summary>
	public class NTRUSigningPublicKeyParameters : AsymmetricKeyParameter
	{
		private NTRUSigningParameters @params;
		public IntegerPolynomial h;

		/// <summary>
		/// Constructs a new public key from a polynomial
		/// </summary>
		/// <param name="h">      the polynomial <code>h</code> which determines the key </param>
		/// <param name="params"> the NtruSign parameters to use </param>
		public NTRUSigningPublicKeyParameters(IntegerPolynomial h, NTRUSigningParameters @params) : base(false)
		{
			this.h = h;
			this.@params = @params;
		}

		/// <summary>
		/// Converts a byte array to a polynomial <code>h</code> and constructs a new public key
		/// </summary>
		/// <param name="b">      an encoded polynomial </param>
		/// <param name="params"> the NtruSign parameters to use </param>
		public NTRUSigningPublicKeyParameters(byte[] b, NTRUSigningParameters @params) : base(false)
		{
			h = IntegerPolynomial.fromBinary(b, @params.N, @params.q);
			this.@params = @params;
		}

		/// <summary>
		/// Reads a polynomial <code>h</code> from an input stream and constructs a new public key
		/// </summary>
		/// <param name="is">     an input stream </param>
		/// <param name="params"> the NtruSign parameters to use </param>
		public NTRUSigningPublicKeyParameters(InputStream @is, NTRUSigningParameters @params) : base(false)
		{
			h = IntegerPolynomial.fromBinary(@is, @params.N, @params.q);
			this.@params = @params;
		}


		/// <summary>
		/// Converts the key to a byte array
		/// </summary>
		/// <returns> the encoded key </returns>
		public virtual byte[] getEncoded()
		{
			return h.toBinary(@params.q);
		}

		/// <summary>
		/// Writes the key to an output stream
		/// </summary>
		/// <param name="os"> an output stream </param>
		/// <exception cref="IOException"> </exception>
		public virtual void writeTo(OutputStream os)
		{
			os.write(getEncoded());
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + ((h == null) ? 0 : h.GetHashCode());
			result = prime * result + ((@params == null) ? 0 : @params.GetHashCode());
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
			NTRUSigningPublicKeyParameters other = (NTRUSigningPublicKeyParameters)obj;
			if (h == null)
			{
				if (other.h != null)
				{
					return false;
				}
			}
			else if (!h.Equals(other.h))
			{
				return false;
			}
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
			return true;
		}
	}
}