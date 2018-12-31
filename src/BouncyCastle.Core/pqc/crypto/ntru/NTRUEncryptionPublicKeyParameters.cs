using System.IO;
using org.bouncycastle.pqc.math.ntru.polynomial;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.pqc.crypto.ntru
{

	
	/// <summary>
	/// A NtruEncrypt public key is essentially a polynomial named <code>h</code>.
	/// </summary>
	public class NTRUEncryptionPublicKeyParameters : NTRUEncryptionKeyParameters
	{
		public IntegerPolynomial h;

		/// <summary>
		/// Constructs a new public key from a polynomial
		/// </summary>
		/// <param name="h">      the polynomial <code>h</code> which determines the key </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		public NTRUEncryptionPublicKeyParameters(IntegerPolynomial h, NTRUEncryptionParameters @params) : base(false, @params)
		{

			this.h = h;
		}

		/// <summary>
		/// Converts a byte array to a polynomial <code>h</code> and constructs a new public key
		/// </summary>
		/// <param name="b">      an encoded polynomial </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		/// <seealso cref= #getEncoded() </seealso>
		public NTRUEncryptionPublicKeyParameters(byte[] b, NTRUEncryptionParameters @params) : base(false, @params)
		{

			h = IntegerPolynomial.fromBinary(b, @params.N, @params.q);
		}

		/// <summary>
		/// Reads a polynomial <code>h</code> from an input stream and constructs a new public key
		/// </summary>
		/// <param name="is">     an input stream </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		/// <seealso cref= #writeTo(OutputStream) </seealso>
		public NTRUEncryptionPublicKeyParameters(InputStream @is, NTRUEncryptionParameters @params) : base(false, @params)
		{

			h = IntegerPolynomial.fromBinary(@is, @params.N, @params.q);
		}

		/// <summary>
		/// Converts the key to a byte array
		/// </summary>
		/// <returns> the encoded key </returns>
		/// <seealso cref= #NTRUEncryptionPublicKeyParameters(byte[], NTRUEncryptionParameters) </seealso>
		public virtual byte[] getEncoded()
		{
			return h.toBinary(@params.q);
		}

		/// <summary>
		/// Writes the key to an output stream
		/// </summary>
		/// <param name="os"> an output stream </param>
		/// <exception cref="IOException"> </exception>
		/// <seealso cref= #NTRUEncryptionPublicKeyParameters(InputStream, NTRUEncryptionParameters) </seealso>
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
			if (!(obj is NTRUEncryptionPublicKeyParameters))
			{
				return false;
			}
			NTRUEncryptionPublicKeyParameters other = (NTRUEncryptionPublicKeyParameters)obj;
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