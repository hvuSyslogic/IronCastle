using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// Cipher parameters with a fixed salt value associated with them.
	/// </summary>
	public class ParametersWithSalt : CipherParameters
	{
		private byte[] salt;
		private CipherParameters parameters;

		public ParametersWithSalt(CipherParameters parameters, byte[] salt) : this(parameters, salt, 0, salt.Length)
		{
		}

		public ParametersWithSalt(CipherParameters parameters, byte[] salt, int saltOff, int saltLen)
		{
			this.salt = new byte[saltLen];
			this.parameters = parameters;

			JavaSystem.arraycopy(salt, saltOff, this.salt, 0, saltLen);
		}

		public virtual byte[] getSalt()
		{
			return salt;
		}

		public virtual CipherParameters getParameters()
		{
			return parameters;
		}
	}

}