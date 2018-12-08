using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.@params
{

	public class ParametersWithIV : CipherParameters
	{
		private byte[] iv;
		private CipherParameters parameters;

		public ParametersWithIV(CipherParameters parameters, byte[] iv) : this(parameters, iv, 0, iv.Length)
		{
		}

		public ParametersWithIV(CipherParameters parameters, byte[] iv, int ivOff, int ivLen)
		{
			this.iv = new byte[ivLen];
			this.parameters = parameters;

			JavaSystem.arraycopy(iv, ivOff, this.iv, 0, ivLen);
		}

		public virtual byte[] getIV()
		{
			return iv;
		}

		public virtual CipherParameters getParameters()
		{
			return parameters;
		}
	}

}