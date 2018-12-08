namespace org.bouncycastle.pqc.crypto.rainbow
{
	public class RainbowPublicKeyParameters : RainbowKeyParameters
	{
		private short[][] coeffquadratic;
		private short[][] coeffsingular;
		private short[] coeffscalar;

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="docLength"> </param>
		/// <param name="coeffQuadratic"> </param>
		/// <param name="coeffSingular"> </param>
		/// <param name="coeffScalar"> </param>
		public RainbowPublicKeyParameters(int docLength, short[][] coeffQuadratic, short[][] coeffSingular, short[] coeffScalar) : base(false, docLength)
		{

			this.coeffquadratic = coeffQuadratic;
			this.coeffsingular = coeffSingular;
			this.coeffscalar = coeffScalar;

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