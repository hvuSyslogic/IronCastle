namespace org.bouncycastle.pqc.crypto.mceliece
{
	using GF2Matrix = org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
	using GF2mField = org.bouncycastle.pqc.math.linearalgebra.GF2mField;
	using GoppaCode = org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
	using Permutation = org.bouncycastle.pqc.math.linearalgebra.Permutation;
	using PolynomialGF2mSmallM = org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
	using PolynomialRingGF2m = org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2m;


	public class McEliecePrivateKeyParameters : McElieceKeyParameters
	{

		// the OID of the algorithm
		private string oid;

		// the length of the code
		private int n;

		// the dimension of the code, where <tt>k &gt;= n - mt</tt>
		private int k;

		// the underlying finite field
		private GF2mField field;

		// the irreducible Goppa polynomial
		private PolynomialGF2mSmallM goppaPoly;

		// a k x k random binary non-singular matrix
		private GF2Matrix sInv;

		// the permutation used to generate the systematic check matrix
		private Permutation p1;

		// the permutation used to compute the public generator matrix
		private Permutation p2;

		// the canonical check matrix of the code
		private GF2Matrix h;

		// the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
		private PolynomialGF2mSmallM[] qInv;

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="n">         the length of the code </param>
		/// <param name="k">         the dimension of the code </param>
		/// <param name="field">     the field polynomial defining the finite field
		///                  <tt>GF(2<sup>m</sup>)</tt> </param>
		/// <param name="gp"> the irreducible Goppa polynomial </param>
		/// <param name="p1">        the permutation used to generate the systematic check
		///                  matrix </param>
		/// <param name="p2">        the permutation used to compute the public generator
		///                  matrix </param>
		/// <param name="sInv">      the matrix <tt>S<sup>-1</sup></tt> </param>
		public McEliecePrivateKeyParameters(int n, int k, GF2mField field, PolynomialGF2mSmallM gp, Permutation p1, Permutation p2, GF2Matrix sInv) : base(true, null)
		{
			this.k = k;
			this.n = n;
			this.field = field;
			this.goppaPoly = gp;
			this.sInv = sInv;
			this.p1 = p1;
			this.p2 = p2;
			this.h = GoppaCode.createCanonicalCheckMatrix(field, gp);

			PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

			  // matrix used to compute square roots in (GF(2^m))^t
			this.qInv = ring.getSquareRootMatrix();
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="n">            the length of the code </param>
		/// <param name="k">            the dimension of the code </param>
		/// <param name="encField">     the encoded field polynomial defining the finite field
		///                     <tt>GF(2<sup>m</sup>)</tt> </param>
		/// <param name="encGoppaPoly"> the encoded irreducible Goppa polynomial </param>
		/// <param name="encSInv">      the encoded matrix <tt>S<sup>-1</sup></tt> </param>
		/// <param name="encP1">        the encoded permutation used to generate the systematic
		///                     check matrix </param>
		/// <param name="encP2">        the encoded permutation used to compute the public
		///                     generator matrix </param>
		/// <param name="encH">         the encoded canonical check matrix </param>
		/// <param name="encQInv">      the encoded matrix used to compute square roots in
		///                     <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt> </param>
		public McEliecePrivateKeyParameters(int n, int k, byte[] encField, byte[] encGoppaPoly, byte[] encSInv, byte[] encP1, byte[] encP2, byte[] encH, byte[][] encQInv) : base(true, null)
		{
			this.n = n;
			this.k = k;
			field = new GF2mField(encField);
			goppaPoly = new PolynomialGF2mSmallM(field, encGoppaPoly);
			sInv = new GF2Matrix(encSInv);
			p1 = new Permutation(encP1);
			p2 = new Permutation(encP2);
			h = new GF2Matrix(encH);
			qInv = new PolynomialGF2mSmallM[encQInv.Length];
			for (int i = 0; i < encQInv.Length; i++)
			{
				qInv[i] = new PolynomialGF2mSmallM(field, encQInv[i]);
			}
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

		/// <returns> the finite field <tt>GF(2<sup>m</sup>)</tt> </returns>
		public virtual GF2mField getField()
		{
			return field;
		}

		/// <returns> the irreducible Goppa polynomial </returns>
		public virtual PolynomialGF2mSmallM getGoppaPoly()
		{
			return goppaPoly;
		}

		/// <returns> the k x k random binary non-singular matrix S^-1 </returns>
		public virtual GF2Matrix getSInv()
		{
			return sInv;
		}

		/// <returns> the permutation used to generate the systematic check matrix </returns>
		public virtual Permutation getP1()
		{
			return p1;
		}

		/// <returns> the permutation used to compute the public generator matrix </returns>
		public virtual Permutation getP2()
		{
			return p2;
		}

		/// <returns> the canonical check matrix H </returns>
		public virtual GF2Matrix getH()
		{
			return h;
		}

		/// <returns> the matrix used to compute square roots in
		///         <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt> </returns>
		public virtual PolynomialGF2mSmallM[] getQInv()
		{
			return qInv;
		}


	}

}