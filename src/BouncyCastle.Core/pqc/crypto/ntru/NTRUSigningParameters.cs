using System.IO;
using BouncyCastle.Core.Port.java.io;
using BouncyCastle.Core.Port.java.lang;
using BouncyCastle.Core.Port.java.text;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.pqc.crypto.ntru
{

	using Digest = org.bouncycastle.crypto.Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;

	/// <summary>
	/// A set of parameters for NtruSign. Several predefined parameter sets are available and new ones can be created as well.
	/// </summary>
	public class NTRUSigningParameters : Cloneable<NTRUSigningParameters>
	{
		public int N;
		public int q;
		public int d, d1, d2, d3, B;
		internal double beta;
		public double betaSq;
		internal double normBound;
		public double normBoundSq;
		public int signFailTolerance = 100;
		internal int bitsF = 6; // max #bits needed to encode one coefficient of the polynomial F
		public Digest hashAlg;

		/// <summary>
		/// Constructs a parameter set that uses ternary private keys (i.e. <code>polyType=SIMPLE</code>).
		/// </summary>
		/// <param name="N">            number of polynomial coefficients </param>
		/// <param name="q">            modulus </param>
		/// <param name="d">            number of -1's in the private polynomials <code>f</code> and <code>g</code> </param>
		/// <param name="B">            number of perturbations </param>
		/// <param name="beta">         balancing factor for the transpose lattice </param>
		/// <param name="normBound">    maximum norm for valid signatures </param>
		/// <param name="hashAlg">      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method. </param>
		public NTRUSigningParameters(int N, int q, int d, int B, double beta, double normBound, Digest hashAlg)
		{
			this.N = N;
			this.q = q;
			this.d = d;
			this.B = B;
			this.beta = beta;
			this.normBound = normBound;
			this.hashAlg = hashAlg;
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
		/// <param name="beta">         balancing factor for the transpose lattice </param>
		/// <param name="normBound">    maximum norm for valid signatures </param>
		/// <param name="keyNormBound"> maximum norm for the ploynomials <code>F</code> and <code>G</code> </param>
		/// <param name="hashAlg">      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method. </param>
		public NTRUSigningParameters(int N, int q, int d1, int d2, int d3, int B, double beta, double normBound, double keyNormBound, Digest hashAlg)
		{
			this.N = N;
			this.q = q;
			this.d1 = d1;
			this.d2 = d2;
			this.d3 = d3;
			this.B = B;
			this.beta = beta;
			this.normBound = normBound;
			this.hashAlg = hashAlg;
			init();
		}

		private void init()
		{
			betaSq = beta * beta;
			normBoundSq = normBound * normBound;
		}

		/// <summary>
		/// Reads a parameter set from an input stream.
		/// </summary>
		/// <param name="is"> an input stream </param>
		/// <exception cref="IOException"> </exception>
		public NTRUSigningParameters(InputStream @is)
		{
			DataInputStream dis = new DataInputStream(@is);
			N = dis.readInt();
			q = dis.readInt();
			d = dis.readInt();
			d1 = dis.readInt();
			d2 = dis.readInt();
			d3 = dis.readInt();
			B = dis.readInt();
			beta = dis.readDouble();
			normBound = dis.readDouble();
			signFailTolerance = dis.readInt();
			bitsF = dis.readInt();
			string alg = dis.readUTF();
			if ("SHA-512".Equals(alg))
			{
				hashAlg = new SHA512Digest();
			}
			else if ("SHA-256".Equals(alg))
			{
				hashAlg = new SHA256Digest();
			}
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
			dos.writeDouble(beta);
			dos.writeDouble(normBound);
			dos.writeInt(signFailTolerance);
			dos.writeInt(bitsF);
			dos.writeUTF(hashAlg.getAlgorithmName());
		}

		public virtual NTRUSigningParameters clone()
		{
			return new NTRUSigningParameters(N, q, d, B, beta, normBound, hashAlg);
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + B;
			result = prime * result + N;
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
			temp = System.BitConverter.DoubleToInt64Bits(normBound);
			result = prime * result + (int)(temp ^ ((long)((ulong)temp >> 32)));
			temp = System.BitConverter.DoubleToInt64Bits(normBoundSq);
			result = prime * result + (int)(temp ^ ((long)((ulong)temp >> 32)));
			result = prime * result + q;
			result = prime * result + signFailTolerance;
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
			if (!(obj is NTRUSigningParameters))
			{
				return false;
			}
			NTRUSigningParameters other = (NTRUSigningParameters)obj;
			if (B != other.B)
			{
				return false;
			}
			if (N != other.N)
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
			if (System.BitConverter.DoubleToInt64Bits(normBound) != Double.doubleToLongBits(other.normBound))
			{
				return false;
			}
			if (System.BitConverter.DoubleToInt64Bits(normBoundSq) != Double.doubleToLongBits(other.normBoundSq))
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

			return true;
		}

		public override string ToString()
		{
			DecimalFormat format = new DecimalFormat("0.00");

			StringBuilder output = new StringBuilder("SignatureParameters(N=" + N + " q=" + q);

			output.append(" B=" + B + " beta=" + format.format(beta) + " normBound=" + format.format(normBound) + " hashAlg=" + hashAlg + ")");
			return output.ToString();
		}
	}

}