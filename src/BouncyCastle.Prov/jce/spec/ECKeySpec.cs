namespace org.bouncycastle.jce.spec
{

	/// <summary>
	/// base class for an Elliptic Curve Key Spec
	/// </summary>
	public class ECKeySpec : KeySpec
	{
		private ECParameterSpec spec;

		public ECKeySpec(ECParameterSpec spec)
		{
			this.spec = spec;
		}

		/// <summary>
		/// return the domain parameters for the curve
		/// </summary>
		public virtual ECParameterSpec getParams()
		{
			return spec;
		}
	}

}