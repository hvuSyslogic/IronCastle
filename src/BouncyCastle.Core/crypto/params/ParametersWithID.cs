namespace org.bouncycastle.crypto.@params
{

	public class ParametersWithID : CipherParameters
	{
		private CipherParameters parameters;
		private byte[] id;

		public ParametersWithID(CipherParameters parameters, byte[] id)
		{
			this.parameters = parameters;
			this.id = id;
		}

		public virtual byte[] getID()
		{
			return id;
		}

		public virtual CipherParameters getParameters()
		{
			return parameters;
		}
	}

}