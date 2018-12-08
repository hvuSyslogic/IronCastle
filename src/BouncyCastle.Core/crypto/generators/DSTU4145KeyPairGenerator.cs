namespace org.bouncycastle.crypto.generators
{
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;

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