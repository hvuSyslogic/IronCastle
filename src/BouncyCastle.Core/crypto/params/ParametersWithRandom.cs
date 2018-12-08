using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{


	public class ParametersWithRandom : CipherParameters
	{
		private SecureRandom random;
		private CipherParameters parameters;

		public ParametersWithRandom(CipherParameters parameters, SecureRandom random)
		{
			this.random = random;
			this.parameters = parameters;
		}

		public ParametersWithRandom(CipherParameters parameters) : this(parameters, CryptoServicesRegistrar.getSecureRandom())
		{
		}

		public virtual SecureRandom getRandom()
		{
			return random;
		}

		public virtual CipherParameters getParameters()
		{
			return parameters;
		}
	}

}