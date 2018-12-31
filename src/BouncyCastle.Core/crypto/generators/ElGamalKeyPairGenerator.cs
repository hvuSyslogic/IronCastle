using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.generators
{

					
	/// <summary>
	/// a ElGamal key pair generator.
	/// <para>
	/// This generates keys consistent for use with ElGamal as described in
	/// page 164 of "Handbook of Applied Cryptography".
	/// </para>
	/// </summary>
	public class ElGamalKeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private ElGamalKeyGenerationParameters param;

		public virtual void init(KeyGenerationParameters param)
		{
			this.param = (ElGamalKeyGenerationParameters)param;
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
			ElGamalParameters egp = param.getParameters();
			DHParameters dhp = new DHParameters(egp.getP(), egp.getG(), null, egp.getL());

			BigInteger x = helper.calculatePrivate(dhp, param.getRandom());
			BigInteger y = helper.calculatePublic(dhp, x);

			return new AsymmetricCipherKeyPair(new ElGamalPublicKeyParameters(y, egp), new ElGamalPrivateKeyParameters(x, egp));
		}
	}

}