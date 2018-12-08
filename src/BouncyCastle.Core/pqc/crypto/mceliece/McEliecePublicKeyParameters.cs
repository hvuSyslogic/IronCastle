namespace org.bouncycastle.pqc.crypto.mceliece
{
	using GF2Matrix = org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;


	public class McEliecePublicKeyParameters : McElieceKeyParameters
	{
		// the length of the code
		private int n;

		// the error correction capability of the code
		private int t;

		// the generator matrix
		private GF2Matrix g;

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="n">      the length of the code </param>
		/// <param name="t">      the error correction capability of the code </param>
		/// <param name="g">      the generator matrix </param>
		public McEliecePublicKeyParameters(int n, int t, GF2Matrix g) : base(false, null)
		{
			this.n = n;
			this.t = t;
			this.g = new GF2Matrix(g);
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

		/// <returns> the generator matrix </returns>
		public virtual GF2Matrix getG()
		{
			return g;
		}

		/// <returns> the dimension of the code </returns>
		public virtual int getK()
		{
			return g.getNumRows();
		}

	}

}