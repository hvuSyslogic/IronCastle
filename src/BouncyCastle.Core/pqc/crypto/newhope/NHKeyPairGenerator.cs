using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;

namespace org.bouncycastle.pqc.crypto.newhope
{

			
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