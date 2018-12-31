using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.generators
{
		
	public class DSTU4145KeyPairGenerator : ECKeyPairGenerator
	{
		public override AsymmetricCipherKeyPair generateKeyPair()
		{
			AsymmetricCipherKeyPair pair = base.generateKeyPair();

			ECPublicKeyParameters pub = (ECPublicKeyParameters)pair.getPublic();
			ECPrivateKeyParameters priv = (ECPrivateKeyParameters)pair.getPrivate();

			pub = new ECPublicKeyParameters(pub.getQ().negate(), pub.getParameters());

			return new AsymmetricCipherKeyPair(pub, priv);
		}
	}

}