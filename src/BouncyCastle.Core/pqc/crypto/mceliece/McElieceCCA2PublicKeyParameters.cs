namespace org.bouncycastle.pqc.crypto.mceliece
{
	using GF2Matrix = org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

	/// 
	/// 
	/// 
	public class McElieceCCA2PublicKeyParameters : McElieceCCA2KeyParameters
	{
		// the length of the code
		private int n;

		// the error correction capability of the code
		private int t;

		// the generator matrix
		private GF2Matrix matrixG;

		/// <summary>
		/// Constructor. </summary>
		///  <param name="n">      length of the code </param>
		/// <param name="t">      error correction capability </param>
		/// <param name="matrix"> generator matrix </param>
		/// <param name="digest"> McElieceCCA2Parameters </param>
		public McElieceCCA2PublicKeyParameters(int n, int t, GF2Matrix matrix, string digest) : base(false, digest)
		{

			this.n = n;
			this.t = t;
			this.matrixG = new GF2Matrix(matrix);
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
			return matrixG;
		}

		/// <returns> the dimension of the code </returns>
		public virtual int getK()
		{
			return matrixG.getNumRows();
		}
	}

}