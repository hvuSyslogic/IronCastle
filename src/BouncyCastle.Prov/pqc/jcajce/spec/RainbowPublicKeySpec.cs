namespace org.bouncycastle.pqc.jcajce.spec
{

	/// <summary>
	/// This class provides a specification for a RainbowSignature public key.
	/// </summary>
	/// <seealso cref= KeySpec </seealso>
	public class RainbowPublicKeySpec : KeySpec
	{
		private short[][] coeffquadratic;
		private short[][] coeffsingular;
		private short[] coeffscalar;
		private int docLength; // length of possible document to sign

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="docLength"> </param>
		/// <param name="coeffquadratic"> </param>
		/// <param name="coeffSingular"> </param>
		/// <param name="coeffScalar"> </param>
		public RainbowPublicKeySpec(int docLength, short[][] coeffquadratic, short[][] coeffSingular, short[] coeffScalar)
		{
			this.docLength = docLength;
			this.coeffquadratic = coeffquadratic;
			this.coeffsingular = coeffSingular;
			this.coeffscalar = coeffScalar;
		}

		/// <returns> the docLength </returns>
		public virtual int getDocLength()
		{
			return this.docLength;
		}

		/// <returns> the coeffquadratic </returns>
		public virtual short[][] getCoeffQuadratic()
		{
			return coeffquadratic;
		}

		/// <returns> the coeffsingular </returns>
		public virtual short[][] getCoeffSingular()
		{
			return coeffsingular;
		}

		/// <returns> the coeffscalar </returns>
		public virtual short[] getCoeffScalar()
		{
			return coeffscalar;
		}
	}

}