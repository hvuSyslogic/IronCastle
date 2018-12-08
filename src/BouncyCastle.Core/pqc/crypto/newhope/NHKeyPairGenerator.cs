using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.crypto.newhope
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using AsymmetricCipherKeyPairGenerator = org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;

	public class NHKeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private SecureRandom random;

		public virtual void init(KeyGenerationParameters param)
		{
			this.random = param.getRandom();
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			byte[] pubData = new byte[NewHope.SENDA_BYTES];
			short[] secData = new short[NewHope.POLY_SIZE];

			NewHope.keygen(random, pubData, secData);

			return new AsymmetricCipherKeyPair(new NHPublicKeyParameters(pubData), new NHPrivateKeyParameters(secData));
		}
	}

}