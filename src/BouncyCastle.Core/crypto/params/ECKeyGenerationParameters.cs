using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class ECKeyGenerationParameters : KeyGenerationParameters
	{
		private ECDomainParameters domainParams;

		public ECKeyGenerationParameters(ECDomainParameters domainParams, SecureRandom random) : base(random, domainParams.getN().bitLength())
		{

			this.domainParams = domainParams;
		}

		public virtual ECDomainParameters getDomainParameters()
		{
			return domainParams;
		}
	}

}