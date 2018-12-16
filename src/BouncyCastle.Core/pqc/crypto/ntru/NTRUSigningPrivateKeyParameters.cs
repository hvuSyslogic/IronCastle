using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.ntru
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DenseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
	using IntegerPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
	using Polynomial = org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
	using ProductFormPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.ProductFormPolynomial;
	using SparseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;

	/// <summary>
	/// A NtruSign private key comprises one or more <seealso cref="NTRUSigningPrivateKeyParameters.Basis"/> of three polynomials each,
	/// except the zeroth basis for which <code>h</code> is undefined.
	/// </summary>
	public class NTRUSigningPrivateKeyParameters : AsymmetricKeyParameter
	{
		private List<Basis> bases;
		private NTRUSigningPublicKeyParameters publicKey;

		/// <summary>
		/// Constructs a new private key from a byte array
		/// </summary>
		/// <param name="b">      an encoded private key </param>
		/// <param name="params"> the NtruSign parameters to use </param>
		public NTRUSigningPrivateKeyParameters(byte[] b, NTRUSigningKeyGenerationParameters @params) : this(new ByteArrayInputStream(b), @params)
		{
		}

		/// <summary>
		/// Constructs a new private key from an input stream
		/// </summary>
		/// <param name="is">     an input stream </param>
		/// <param name="params"> the NtruSign parameters to use </param>
		public NTRUSigningPrivateKeyParameters(InputStream @is, NTRUSigningKeyGenerationParameters @params) : base(true)
		{
			bases = new ArrayList<Basis>();
			for (int i = 0; i <= @params.B; i++)
			{
			// include a public key h[i] in all bases except for the first one
				add(new Basis(@is, @params, i != 0));
			}
			publicKey = new NTRUSigningPublicKeyParameters(@is, @params.getSigningParameters());
		}

		public NTRUSigningPrivateKeyParameters(List<Basis> bases, NTRUSigningPublicKeyParameters publicKey) : base(true)
		{
			this.bases = new ArrayList<Basis>(bases);
			this.publicKey = publicKey;
		}

		/// <summary>
		/// Adds a basis to the key.
		/// </summary>
		/// <param name="b"> a NtruSign basis </param>
		private void add(Basis b)
		{
			bases.add(b);
		}

		/// <summary>
		/// Returns the <code>i</code>-th basis
		/// </summary>
		/// <param name="i"> the index </param>
		/// <returns> the basis at index <code>i</code> </returns>
		public virtual Basis getBasis(int i)
		{
			return bases.get(i);
		}

		public virtual NTRUSigningPublicKeyParameters getPublicKey()
		{
			return publicKey;
		}

		/// <summary>
		/// Converts the key to a byte array
		/// </summary>
		/// <returns> the encoded key </returns>
		public virtual byte[] getEncoded()
		{
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			for (int i = 0; i < bases.size(); i++)
			{
				// all bases except for the first one contain a public key
				bases.get(i).encode(os, i != 0);
			}

			os.write(publicKey.getEncoded());

			return os.toByteArray();
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
			result = prime * result;
			if (bases == null)
			{
				return result;
			}
			result += bases.GetHashCode();
			foreach (Basis basis in bases)
			{
				result += basis.GetHashCode();
			}
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
			NTRUSigningPrivateKeyParameters other = (NTRUSigningPrivateKeyParameters)obj;
			if ((bases == null) != (other.bases == null))
			{
				return false;
			}
			if (bases == null)
			{
				return true;
			}
			if (bases.size() != other.bases.size())
			{
				return false;
			}
			for (int i = 0; i < bases.size(); i++)
			{
				Basis basis1 = bases.get(i);
				Basis basis2 = other.bases.get(i);
				if (!basis1.Equals(basis2))
				{
					return false;
				}
				if (!basis1.fPrime.Equals(basis2.fPrime))
				{
					return false;
				}
				if (i != 0 && !basis1.h.Equals(basis2.h)) // don't compare h for the 0th basis
				{
					return false;
				}
				if (!basis1.@params.Equals(basis2.@params))
				{
					return false;
				}
			}
			return true;
		}

		/// <summary>
		/// A NtruSign basis. Contains three polynomials <code>f, f', h</code>.
		/// </summary>
		public class Basis
		{
			public Polynomial f;
			public Polynomial fPrime;
			public IntegerPolynomial h;
			internal NTRUSigningKeyGenerationParameters @params;

			/// <summary>
			/// Constructs a new basis from polynomials <code>f, f', h</code>.
			/// </summary>
			/// <param name="f"> </param>
			/// <param name="fPrime"> </param>
			/// <param name="h"> </param>
			/// <param name="params"> NtruSign parameters </param>
			public Basis(Polynomial f, Polynomial fPrime, IntegerPolynomial h, NTRUSigningKeyGenerationParameters @params)
			{
				this.f = f;
				this.fPrime = fPrime;
				this.h = h;
				this.@params = @params;
			}

			/// <summary>
			/// Reads a basis from an input stream and constructs a new basis.
			/// </summary>
			/// <param name="is">        an input stream </param>
			/// <param name="params">    NtruSign parameters </param>
			/// <param name="include_h"> whether to read the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>) </param>
			public Basis(InputStream @is, NTRUSigningKeyGenerationParameters @params, bool include_h)
			{
				int N = @params.N;
				int q = @params.q;
				int d1 = @params.d1;
				int d2 = @params.d2;
				int d3 = @params.d3;
				bool sparse = @params.sparse;
				this.@params = @params;

				if (@params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT)
				{
					f = ProductFormPolynomial.fromBinary(@is, N, d1, d2, d3 + 1, d3);
				}
				else
				{
					IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Tight(@is, N);
					f = sparse ? (Polynomial) new SparseTernaryPolynomial(fInt) : new DenseTernaryPolynomial(fInt);
				}

				if (@params.basisType == NTRUSigningKeyGenerationParameters.BASIS_TYPE_STANDARD)
				{
					IntegerPolynomial fPrimeInt = IntegerPolynomial.fromBinary(@is, N, q);
					for (int i = 0; i < fPrimeInt.coeffs.Length; i++)
					{
						fPrimeInt.coeffs[i] -= q / 2;
					}
					fPrime = fPrimeInt;
				}
				else if (@params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT)
				{
					fPrime = ProductFormPolynomial.fromBinary(@is, N, d1, d2, d3 + 1, d3);
				}
				else
				{
					fPrime = IntegerPolynomial.fromBinary3Tight(@is, N);
				}

				if (include_h)
				{
					h = IntegerPolynomial.fromBinary(@is, N, q);
				}
			}

			/// <summary>
			/// Writes the basis to an output stream
			/// </summary>
			/// <param name="os">        an output stream </param>
			/// <param name="include_h"> whether to write the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>) </param>
			/// <exception cref="IOException"> </exception>
			public virtual void encode(OutputStream os, bool include_h)
			{
				int q = @params.q;

				os.write(getEncoded(f));
				if (@params.basisType == NTRUSigningKeyGenerationParameters.BASIS_TYPE_STANDARD)
				{
					IntegerPolynomial fPrimeInt = fPrime.toIntegerPolynomial();
					for (int i = 0; i < fPrimeInt.coeffs.Length; i++)
					{
						fPrimeInt.coeffs[i] += q / 2;
					}
					os.write(fPrimeInt.toBinary(q));
				}
				else
				{
					os.write(getEncoded(fPrime));
				}
				if (include_h)
				{
					os.write(h.toBinary(q));
				}
			}

			public virtual byte[] getEncoded(Polynomial p)
			{
				if (p is ProductFormPolynomial)
				{
					return ((ProductFormPolynomial)p).toBinary();
				}
				else
				{
					return p.toIntegerPolynomial().toBinary3Tight();
				}
			}

			public override int GetHashCode()
			{
				const int prime = 31;
				int result = 1;
				result = prime * result + ((f == null) ? 0 : f.GetHashCode());
				result = prime * result + ((fPrime == null) ? 0 : fPrime.GetHashCode());
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
				if (!(obj is Basis))
				{
					return false;
				}
				Basis other = (Basis)obj;
				if (f == null)
				{
					if (other.f != null)
					{
						return false;
					}
				}
				else if (!f.Equals(other.f))
				{
					return false;
				}
				if (fPrime == null)
				{
					if (other.fPrime != null)
					{
						return false;
					}
				}
				else if (!fPrime.Equals(other.fPrime))
				{
					return false;
				}
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

}