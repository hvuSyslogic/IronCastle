namespace org.bouncycastle.jcajce.provider.asymmetric.util
{


	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPrivateKeyParameters = org.bouncycastle.crypto.@params.DHPrivateKeyParameters;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;
	using BCDHPublicKey = org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey;

	/// <summary>
	/// utility class for converting jce/jca DH objects
	/// objects into their org.bouncycastle.crypto counterparts.
	/// </summary>
	public class DHUtil
	{
		public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			if (key is BCDHPublicKey)
			{
				return ((BCDHPublicKey)key).engineGetKeyParameters();
			}
			if (key is DHPublicKey)
			{
				DHPublicKey k = (DHPublicKey)key;

				return new DHPublicKeyParameters(k.getY(), new DHParameters(k.getParams().getP(), k.getParams().getG(), null, k.getParams().getL()));
			}

			throw new InvalidKeyException("can't identify DH public key.");
		}

		public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
		{
			if (key is DHPrivateKey)
			{
				DHPrivateKey k = (DHPrivateKey)key;

				return new DHPrivateKeyParameters(k.getX(), new DHParameters(k.getParams().getP(), k.getParams().getG(), null, k.getParams().getL()));
			}

			throw new InvalidKeyException("can't identify DH private key.");
		}
	}

}