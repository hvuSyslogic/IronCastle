namespace org.bouncycastle.jce.spec
{

	public class ElGamalKeySpec : KeySpec
	{
		private ElGamalParameterSpec spec;

		public ElGamalKeySpec(ElGamalParameterSpec spec)
		{
			this.spec = spec;
		}

		public virtual ElGamalParameterSpec getParams()
		{
			return spec;
		}
	}

}