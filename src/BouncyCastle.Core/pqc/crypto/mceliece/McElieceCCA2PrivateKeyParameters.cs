using org.bouncycastle.pqc.math.linearalgebra;

namespace org.bouncycastle.pqc.crypto.mceliece
{

						
	/// 
	/// 
	/// 
	public class McElieceCCA2PrivateKeyParameters : McElieceCCA2KeyParameters
	{
		// the length of the code
		private int n;

		// the dimension of the code
		private int k;

		// the finte field GF(2^m)
		private GF2mField field;

		// the irreducible Goppa polynomial
		private PolynomialGF2mSmallM goppaPoly;

		// the permutation
		private Permutation p;

		// the canonical check matrix
		private GF2Matrix h;

		// the matrix used to compute square roots in (GF(2^m))^t
		private PolynomialGF2mSmallM[] qInv;

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="n">      the length of the code </param>
		/// <param name="k">      the dimension of the code </param>
		/// <param name="field">  the finite field <tt>GF(2<sup>m</sup>)</tt> </param>
		/// <param name="gp">     the irreducible Goppa polynomial </param>
		/// <param name="p">      the permutation </param>
		/// <param name="digest"> name of digest algorithm </param>
		public McElieceCCA2PrivateKeyParameters(int n, int k, GF2mField field, PolynomialGF2mSmallM gp, Permutation p, string digest) : this(n, k, field, gp, GoppaCode.createCanonicalCheckMatrix(field, gp), p, digest)
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="n">                         the length of the code </param>
		/// <param name="k">                         the dimension of the code </param>
		/// <param name="field">                     the finite field <tt>GF(2<sup>m</sup>)</tt> </param>
		/// <param name="gp">                        the irreducible Goppa polynomial </param>
		/// <param name="canonicalCheckMatrix">      the canonical check matrix </param>
		/// <param name="p">                         the permutation </param>
		/// <param name="digest">                    name of digest algorithm </param>
		public McElieceCCA2PrivateKeyParameters(int n, int k, GF2mField field, PolynomialGF2mSmallM gp, GF2Matrix canonicalCheckMatrix, Permutation p, string digest) : base(true, digest)
		{

			this.n = n;
			this.k = k;
			this.field = field;
			this.goppaPoly = gp;
			this.h = canonicalCheckMatrix;
			this.p = p;

			PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

			// matrix for computing square roots in (GF(2^m))^t
			this.qInv = ring.getSquareRootMatrix();
		}

		/// <returns> the length of the code </returns>
		public virtual int getN()
		{
			return n;
		}

		/// <returns> the dimension of the code </returns>
		public virtual int getK()
		{
			return k;
		}

		/// <returns> the degree of the Goppa polynomial (error correcting capability) </returns>
		public virtual int getT()
		{
			return goppaPoly.getDegree();
		}

		/// <returns> the finite field </returns>
		public virtual GF2mField getField()
		{
			return field;
		}

		/// <returns> the irreducible Goppa polynomial </returns>
		public virtual PolynomialGF2mSmallM getGoppaPoly()
		{
			return goppaPoly;
		}

		/// <returns> the permutation P </returns>
		public virtual Permutation getP()
		{
			return p;
		}

		/// <returns> the canonical check matrix H </returns>
		public virtual GF2Matrix getH()
		{
			return h;
		}

		/// <returns> the matrix used to compute square roots in <tt>(GF(2^m))^t</tt> </returns>
		public virtual PolynomialGF2mSmallM[] getQInv()
		{
			return qInv;
		}
	}

}