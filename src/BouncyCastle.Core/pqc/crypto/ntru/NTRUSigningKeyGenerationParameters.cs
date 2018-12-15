using System.IO;
using BouncyCastle.Core.Port.java.io;
using BouncyCastle.Core.Port.java.lang;
using BouncyCastle.Core.Port.java.text;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.pqc.crypto.ntru
{

	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using Digest = org.bouncycastle.crypto.Digest;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;

	/// <summary>
	/// A set of parameters for NtruSign. Several predefined parameter sets are available and new ones can be created as well.
	/// </summary>
	public class NTRUSigningKeyGenerationParameters : KeyGenerationParameters, Cloneable<NTRUSigningKeyGenerationParameters>
	{
		public const int BASIS_TYPE_STANDARD = 0;
		public const int BASIS_TYPE_TRANSPOSE = 1;

		public const int KEY_GEN_ALG_RESULTANT = 0;
		public const int KEY_GEN_ALG_FLOAT = 1;

		/// <summary>
		/// Gives 128 bits of security
		/// </summary>
		public static readonly NTRUSigningKeyGenerationParameters APR2011_439 = new NTRUSigningKeyGenerationParameters(439, 2048, 146, 1, BASIS_TYPE_TRANSPOSE, 0.165, 490, 280, false, true, KEY_GEN_ALG_RESULTANT, new SHA256Digest());

		/// <summary>
		/// Like <code>APR2011_439</code>, this parameter set gives 128 bits of security but uses product-form polynomials
		/// </summary>
		public static readonly NTRUSigningKeyGenerationParameters APR2011_439_PROD = new NTRUSigningKeyGenerationParameters(439, 2048, 9, 8, 5, 1, BASIS_TYPE_TRANSPOSE, 0.165, 490, 280, false, true, KEY_GEN_ALG_RESULTANT, new SHA256Digest());

		/// <summary>
		/// Gives 256 bits of security
		/// </summary>
		public static readonly NTRUSigningKeyGenerationParameters APR2011_743 = new NTRUSigningKeyGenerationParameters(743, 2048, 248, 1, BASIS_TYPE_TRANSPOSE, 0.127, 560, 360, true, false, KEY_GEN_ALG_RESULTANT, new SHA512Digest());

		/// <summary>
		/// Like <code>APR2011_439</code>, this parameter set gives 256 bits of security but uses product-form polynomials
		/// </summary>
		public static readonly NTRUSigningKeyGenerationParameters APR2011_743_PROD = new NTRUSigningKeyGenerationParameters(743, 2048, 11, 11, 15, 1, BASIS_TYPE_TRANSPOSE, 0.127, 560, 360, true, false, KEY_GEN_ALG_RESULTANT, new SHA512Digest());

		/// <summary>
		/// Generates key pairs quickly. Use for testing only.
		/// </summary>
		public static readonly NTRUSigningKeyGenerationParameters TEST157 = new NTRUSigningKeyGenerationParameters(157, 256, 29, 1, BASIS_TYPE_TRANSPOSE, 0.38, 200, 80, false, false, KEY_GEN_ALG_RESULTANT, new SHA256Digest());
		/// <summary>
		/// Generates key pairs quickly. Use for testing only.
		/// </summary>
		public static readonly NTRUSigningKeyGenerationParameters TEST157_PROD = new NTRUSigningKeyGenerationParameters(157, 256, 5, 5, 8, 1, BASIS_TYPE_TRANSPOSE, 0.38, 200, 80, false, false, KEY_GEN_ALG_RESULTANT, new SHA256Digest());


		public int N;
		public int q;
		public int d, d1, d2, d3, B;
		internal double beta;
		public double betaSq;
		internal double normBound;
		public double normBoundSq;
		public int signFailTolerance = 100;
		internal double keyNormBound;
		public double keyNormBoundSq;
		public bool primeCheck; // true if N and 2N+1 are prime
		public int basisType;
		internal int bitsF = 6; // max #bits needed to encode one coefficient of the polynomial F
		public bool sparse; // whether to treat ternary polynomials as sparsely populated
		public int keyGenAlg;
		public Digest hashAlg;
		public int polyType;

		/// <summary>
		/// Constructs a parameter set that uses ternary private keys (i.e. <code>polyType=SIMPLE</code>).
		/// </summary>
		/// <param name="N">            number of polynomial coefficients </param>
		/// <param name="q">            modulus </param>
		/// <param name="d">            number of -1's in the private polynomials <code>f</code> and <code>g</code> </param>
		/// <param name="B">            number of perturbations </param>
		/// <param name="basisType">    whether to use the standard or transpose lattice </param>
		/// <param name="beta">         balancing factor for the transpose lattice </param>
		/// <param name="normBound">    maximum norm for valid signatures </param>
		/// <param name="keyNormBound"> maximum norm for the ploynomials <code>F</code> and <code>G</code> </param>
		/// <param name="primeCheck">   whether <code>2N+1</code> is prime </param>
		/// <param name="sparse">       whether to treat ternary polynomials as sparsely populated (<seealso cref="org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial"/> vs <seealso cref="org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial"/>) </param>
		/// <param name="keyGenAlg">    <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is slightly faster. <code>RESULTANT</code> follows the EESS standard while <code>FLOAT</code> is described in Hoffstein et al: An Introduction to Mathematical Cryptography. </param>
		/// <param name="hashAlg">      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method. </param>
		public NTRUSigningKeyGenerationParameters(int N, int q, int d, int B, int basisType, double beta, double normBound, double keyNormBound, bool primeCheck, bool sparse, int keyGenAlg, Digest hashAlg) : base(CryptoServicesRegistrar.getSecureRandom(), N)
		{
			this.N = N;
			this.q = q;
			this.d = d;
			this.B = B;
			this.basisType = basisType;
			this.beta = beta;
			this.normBound = normBound;
			this.keyNormBound = keyNormBound;
			this.primeCheck = primeCheck;
			this.sparse = sparse;
			this.keyGenAlg = keyGenAlg;
			this.hashAlg = hashAlg;
			polyType = NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE;
			init();
		}

		/// <summary>
		/// Constructs a parameter set that uses product-form private keys (i.e. <code>polyType=PRODUCT</code>).
		/// </summary>
		/// <param name="N">            number of polynomial coefficients </param>
		/// <param name="q">            modulus </param>
		/// <param name="d1">           number of -1's in the private polynomials <code>f</code> and <code>g</code> </param>
		/// <param name="d2">           number of -1's in the private polynomials <code>f</code> and <code>g</code> </param>
		/// <param name="d3">           number of -1's in the private polynomials <code>f</code> and <code>g</code> </param>
		/// <param name="B">            number of perturbations </param>
		/// <param name="basisType">    whether to use the standard or transpose lattice </param>
		/// <param name="beta">         balancing factor for the transpose lattice </param>
		/// <param name="normBound">    maximum norm for valid signatures </param>
		/// <param name="keyNormBound"> maximum norm for the ploynomials <code>F</code> and <code>G</code> </param>
		/// <param name="primeCheck">   whether <code>2N+1</code> is prime </param>
		/// <param name="sparse">       whether to treat ternary polynomials as sparsely populated (<seealso cref="org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial"/> vs <seealso cref="org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial"/>) </param>
		/// <param name="keyGenAlg">    <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is slightly faster. <code>RESULTANT</code> follows the EESS standard while <code>FLOAT</code> is described in Hoffstein et al: An Introduction to Mathematical Cryptography. </param>
		/// <param name="hashAlg">      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method. </param>
		public NTRUSigningKeyGenerationParameters(int N, int q, int d1, int d2, int d3, int B, int basisType, double beta, double normBound, double keyNormBound, bool primeCheck, bool sparse, int keyGenAlg, Digest hashAlg) : base(CryptoServicesRegistrar.getSecureRandom(), N)
		{
			this.N = N;
			this.q = q;
			this.d1 = d1;
			this.d2 = d2;
			this.d3 = d3;
			this.B = B;
			this.basisType = basisType;
			this.beta = beta;
			this.normBound = normBound;
			this.keyNormBound = keyNormBound;
			this.primeCheck = primeCheck;
			this.sparse = sparse;
			this.keyGenAlg = keyGenAlg;
			this.hashAlg = hashAlg;
			polyType = NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT;
			init();
		}

		private void init()
		{
			betaSq = beta * beta;
			normBoundSq = normBound * normBound;
			keyNormBoundSq = keyNormBound * keyNormBound;
		}

		/// <summary>
		/// Reads a parameter set from an input stream.
		/// </summary>
		/// <param name="is"> an input stream </param>
		/// <exception cref="IOException"> </exception>
		public NTRUSigningKeyGenerationParameters(InputStream @is) : base(CryptoServicesRegistrar.getSecureRandom(), 0) // TODO:
		{
			DataInputStream dis = new DataInputStream(@is);
			N = dis.readInt();
			q = dis.readInt();
			d = dis.readInt();
			d1 = dis.readInt();
			d2 = dis.readInt();
			d3 = dis.readInt();
			B = dis.readInt();
			basisType = dis.readInt();
			beta = dis.readDouble();
			normBound = dis.readDouble();
			keyNormBound = dis.readDouble();
			signFailTolerance = dis.readInt();
			primeCheck = dis.readBoolean();
			sparse = dis.readBoolean();
			bitsF = dis.readInt();
			keyGenAlg = dis.read();
			string alg = dis.readUTF();
			if ("SHA-512".Equals(alg))
			{
				hashAlg = new SHA512Digest();
			}
			else if ("SHA-256".Equals(alg))
			{
				hashAlg = new SHA256Digest();
			}
			polyType = dis.read();
			init();
		}

		/// <summary>
		/// Writes the parameter set to an output stream
		/// </summary>
		/// <param name="os"> an output stream </param>
		/// <exception cref="IOException"> </exception>
		public virtual void writeTo(OutputStream os)
		{
			DataOutputStream dos = new DataOutputStream(os);
			dos.writeInt(N);
			dos.writeInt(q);
			dos.writeInt(d);
			dos.writeInt(d1);
			dos.writeInt(d2);
			dos.writeInt(d3);
			dos.writeInt(B);
			dos.writeInt(basisType);
			dos.writeDouble(beta);
			dos.writeDouble(normBound);
			dos.writeDouble(keyNormBound);
			dos.writeInt(signFailTolerance);
			dos.writeBoolean(primeCheck);
			dos.writeBoolean(sparse);
			dos.writeInt(bitsF);
			dos.write(keyGenAlg);
			dos.writeUTF(hashAlg.getAlgorithmName());
			dos.write(polyType);
		}

		public virtual NTRUSigningParameters getSigningParameters()
		{
			return new NTRUSigningParameters(N, q, d, B, beta, normBound, hashAlg);
		}

		public virtual NTRUSigningKeyGenerationParameters clone()
		{
			if (polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE)
			{
				return new NTRUSigningKeyGenerationParameters(N, q, d, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg, hashAlg);
			}
			else
			{
				return new NTRUSigningKeyGenerationParameters(N, q, d1, d2, d3, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg, hashAlg);
			}
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + B;
			result = prime * result + N;
			result = prime * result + basisType;
			long temp;
			temp = System.BitConverter.DoubleToInt64Bits(beta);
			result = prime * result + (int)(temp ^ ((long)((ulong)temp >> 32)));
			temp = System.BitConverter.DoubleToInt64Bits(betaSq);
			result = prime * result + (int)(temp ^ ((long)((ulong)temp >> 32)));
			result = prime * result + bitsF;
			result = prime * result + d;
			result = prime * result + d1;
			result = prime * result + d2;
			result = prime * result + d3;
			result = prime * result + ((hashAlg == null) ? 0 : hashAlg.getAlgorithmName().GetHashCode());
			result = prime * result + keyGenAlg;
			temp = System.BitConverter.DoubleToInt64Bits(keyNormBound);
			result = prime * result + (int)(temp ^ ((long)((ulong)temp >> 32)));
			temp = System.BitConverter.DoubleToInt64Bits(keyNormBoundSq);
			result = prime * result + (int)(temp ^ ((long)((ulong)temp >> 32)));
			temp = System.BitConverter.DoubleToInt64Bits(normBound);
			result = prime * result + (int)(temp ^ ((long)((ulong)temp >> 32)));
			temp = System.BitConverter.DoubleToInt64Bits(normBoundSq);
			result = prime * result + (int)(temp ^ ((long)((ulong)temp >> 32)));
			result = prime * result + polyType;
			result = prime * result + (primeCheck ? 1231 : 1237);
			result = prime * result + q;
			result = prime * result + signFailTolerance;
			result = prime * result + (sparse ? 1231 : 1237);
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
			if (!(obj is NTRUSigningKeyGenerationParameters))
			{
				return false;
			}
			NTRUSigningKeyGenerationParameters other = (NTRUSigningKeyGenerationParameters)obj;
			if (B != other.B)
			{
				return false;
			}
			if (N != other.N)
			{
				return false;
			}
			if (basisType != other.basisType)
			{
				return false;
			}
			if (System.BitConverter.DoubleToInt64Bits(beta) != Double.doubleToLongBits(other.beta))
			{
				return false;
			}
			if (System.BitConverter.DoubleToInt64Bits(betaSq) != Double.doubleToLongBits(other.betaSq))
			{
				return false;
			}
			if (bitsF != other.bitsF)
			{
				return false;
			}
			if (d != other.d)
			{
				return false;
			}
			if (d1 != other.d1)
			{
				return false;
			}
			if (d2 != other.d2)
			{
				return false;
			}
			if (d3 != other.d3)
			{
				return false;
			}
			if (hashAlg == null)
			{
				if (other.hashAlg != null)
				{
					return false;
				}
			}
			else if (!hashAlg.getAlgorithmName().Equals(other.hashAlg.getAlgorithmName()))
			{
				return false;
			}
			if (keyGenAlg != other.keyGenAlg)
			{
				return false;
			}
			if (System.BitConverter.DoubleToInt64Bits(keyNormBound) != Double.doubleToLongBits(other.keyNormBound))
			{
				return false;
			}
			if (System.BitConverter.DoubleToInt64Bits(keyNormBoundSq) != Double.doubleToLongBits(other.keyNormBoundSq))
			{
				return false;
			}
			if (System.BitConverter.DoubleToInt64Bits(normBound) != Double.doubleToLongBits(other.normBound))
			{
				return false;
			}
			if (System.BitConverter.DoubleToInt64Bits(normBoundSq) != Double.doubleToLongBits(other.normBoundSq))
			{
				return false;
			}
			if (polyType != other.polyType)
			{
				return false;
			}
			if (primeCheck != other.primeCheck)
			{
				return false;
			}
			if (q != other.q)
			{
				return false;
			}
			if (signFailTolerance != other.signFailTolerance)
			{
				return false;
			}
			if (sparse != other.sparse)
			{
				return false;
			}
			return true;
		}

		public override string ToString()
		{
			DecimalFormat format = new DecimalFormat("0.00");

			StringBuilder output = new StringBuilder("SignatureParameters(N=" + N + " q=" + q);
			if (polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE)
			{
				output.append(" polyType=SIMPLE d=" + d);
			}
			else
			{
				output.append(" polyType=PRODUCT d1=" + d1 + " d2=" + d2 + " d3=" + d3);
			}
			output.append(" B=" + B + " basisType=" + basisType + " beta=" + format.format(beta) + " normBound=" + format.format(normBound) + " keyNormBound=" + format.format(keyNormBound) + " prime=" + primeCheck + " sparse=" + sparse + " keyGenAlg=" + keyGenAlg + " hashAlg=" + hashAlg + ")");
			return output.ToString();
		}
	}

}