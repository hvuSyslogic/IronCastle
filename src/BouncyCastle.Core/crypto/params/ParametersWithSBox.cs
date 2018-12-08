namespace org.bouncycastle.crypto.@params
{

	public class ParametersWithSBox : CipherParameters
	{
		private CipherParameters parameters;
		private byte[] sBox;

		public ParametersWithSBox(CipherParameters parameters, byte[] sBox)
		{
			this.parameters = parameters;
			this.sBox = sBox;
		}

		public virtual byte[] getSBox()
		{
			return sBox;
		}

		public virtual CipherParameters getParameters()
		{
			return parameters;
		}
	}

}