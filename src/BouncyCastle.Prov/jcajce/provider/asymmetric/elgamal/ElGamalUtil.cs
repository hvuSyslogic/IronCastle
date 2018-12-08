namespace org.bouncycastle.jcajce.provider.asymmetric.elgamal
{


	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ElGamalParameters = org.bouncycastle.crypto.@params.ElGamalParameters;
	using ElGamalPrivateKeyParameters = org.bouncycastle.crypto.@params.ElGamalPrivateKeyParameters;
	using ElGamalPublicKeyParameters = org.bouncycastle.crypto.@params.ElGamalPublicKeyParameters;
	using ElGamalPrivateKey = org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
	using ElGamalPublicKey = org.bouncycastle.jce.interfaces.ElGamalPublicKey;

	/// <summary>
	/// utility class for converting jce/jca ElGamal objects
	/// objects into their org.bouncycastle.crypto counterparts.
	/// </summary>
	public class ElGamalUtil
	{
		public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			if (key is ElGamalPublicKey)
			{
				ElGamalPublicKey k = (ElGamalPublicKey)key;

				return new ElGamalPublicKeyParameters(k.getY(), new ElGamalParameters(k.getParameters().getP(), k.getParameters().getG()));
			}
			else if (key is DHPublicKey)
			{
				DHPublicKey k = (DHPublicKey)key;

				return new ElGamalPublicKeyParameters(k.getY(), new ElGamalParameters(k.getParams().getP(), k.getParams().getG()));
			}

			throw new InvalidKeyException("can't identify public key for El Gamal.");
		}

		public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
		{
			if (key is ElGamalPrivateKey)
			{
				ElGamalPrivateKey k = (ElGamalPrivateKey)key;

				return new ElGamalPrivateKeyParameters(k.getX(), new ElGamalParameters(k.getParameters().getP(), k.getParameters().getG()));
			}
			else if (key is DHPrivateKey)
			{
				DHPrivateKey k = (DHPrivateKey)key;

				return new ElGamalPrivateKeyParameters(k.getX(), new ElGamalParameters(k.getParams().getP(), k.getParams().getG()));
			}

			throw new InvalidKeyException("can't identify private key for El Gamal.");
		}
	}

}