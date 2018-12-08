using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.@params
{

	public class ParametersWithUKM : CipherParameters
	{
		private byte[] ukm;
		private CipherParameters parameters;

		public ParametersWithUKM(CipherParameters parameters, byte[] ukm) : this(parameters, ukm, 0, ukm.Length)
		{
		}

		public ParametersWithUKM(CipherParameters parameters, byte[] ukm, int ivOff, int ivLen)
		{
			this.ukm = new byte[ivLen];
			this.parameters = parameters;

			JavaSystem.arraycopy(ukm, ivOff, this.ukm, 0, ivLen);
		}

		public virtual byte[] getUKM()
		{
			return ukm;
		}

		public virtual CipherParameters getParameters()
		{
			return parameters;
		}
	}

}