using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.generators
{

	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using ElGamalKeyGenerationParameters = org.bouncycastle.crypto.@params.ElGamalKeyGenerationParameters;
	using ElGamalParameters = org.bouncycastle.crypto.@params.ElGamalParameters;
	using ElGamalPrivateKeyParameters = org.bouncycastle.crypto.@params.ElGamalPrivateKeyParameters;
	using ElGamalPublicKeyParameters = org.bouncycastle.crypto.@params.ElGamalPublicKeyParameters;

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