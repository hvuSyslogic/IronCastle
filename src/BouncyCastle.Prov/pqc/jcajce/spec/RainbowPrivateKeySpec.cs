namespace org.bouncycastle.pqc.jcajce.spec
{

	using Layer = org.bouncycastle.pqc.crypto.rainbow.Layer;

	/// <summary>
	/// This class provides a specification for a RainbowSignature private key.
	/// </summary>
	/// <seealso cref= KeySpec </seealso>
	public class RainbowPrivateKeySpec : KeySpec
	{
		/*
		  * invertible affine linear map L1
		  */
		// the inverse of A1, (n-v1 x n-v1 matrix)
		private short[][] A1inv;

		// translation vector of L1
		private short[] b1;

		/*
		  * invertible affine linear map L2
		  */
		// the inverse of A2, (n x n matrix)
		private short[][] A2inv;

		// translation vector of L2
		private short[] b2;

		/*
		  * components of F
		  */
		// the number of Vinegar-variables per layer.
		private int[] vi;

		// contains the polynomials with their coefficients of private map F
		private Layer[] layers;

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="A1inv">  the inverse of A1(the matrix part of the affine linear map L1)
		///               (n-v1 x n-v1 matrix) </param>
		/// <param name="b1">     translation vector, part of the linear affine map L1 </param>
		/// <param name="A2inv">  the inverse of A2(the matrix part of the affine linear map L2)
		///               (n x n matrix) </param>
		/// <param name="b2">     translation vector, part of the linear affine map L2 </param>
		/// <param name="vi">     the number of Vinegar-variables per layer </param>
		/// <param name="layers"> the polynomials with their coefficients of private map F </param>
		public RainbowPrivateKeySpec(short[][] A1inv, short[] b1, short[][] A2inv, short[] b2, int[] vi, Layer[] layers)
		{
			this.A1inv = A1inv;
			this.b1 = b1;
			this.A2inv = A2inv;
			this.b2 = b2;
			this.vi = vi;
			this.layers = layers;
		}

		/// <summary>
		/// Getter for the translation part of the private quadratic map L1.
		/// </summary>
		/// <returns> b1 the translation part of L1 </returns>
		public virtual short[] getB1()
		{
			return this.b1;
		}

		/// <summary>
		/// Getter for the inverse matrix of A1.
		/// </summary>
		/// <returns> the A1inv inverse </returns>
		public virtual short[][] getInvA1()
		{
			return this.A1inv;
		}

		/// <summary>
		/// Getter for the translation part of the private quadratic map L2.
		/// </summary>
		/// <returns> b2 the translation part of L2 </returns>
		public virtual short[] getB2()
		{
			return this.b2;
		}

		/// <summary>
		/// Getter for the inverse matrix of A2
		/// </summary>
		/// <returns> the A2inv </returns>
		public virtual short[][] getInvA2()
		{
			return this.A2inv;
		}

		/// <summary>
		/// Returns the layers contained in the private key
		/// </summary>
		/// <returns> layers </returns>
		public virtual Layer[] getLayers()
		{
			return this.layers;
		}

		/// <summary>
		/// /** Returns the array of vi-s
		/// </summary>
		/// <returns> the vi </returns>
		public virtual int[] getVi()
		{
			return vi;
		}

	}

}