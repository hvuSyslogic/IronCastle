using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class GOST3410KeyGenerationParameters : KeyGenerationParameters
	{
			private GOST3410Parameters @params;

			public GOST3410KeyGenerationParameters(SecureRandom random, GOST3410Parameters @params) : base(random, @params.getP().bitLength() - 1)
			{

				this.@params = @params;
			}

			public virtual GOST3410Parameters getParameters()
			{
				return @params;
			}
	}

}