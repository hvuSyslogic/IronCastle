namespace org.bouncycastle.pqc.jcajce.provider.rainbow
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using RainbowPrivateKeyParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
	using RainbowPublicKeyParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;


	/// <summary>
	/// utility class for converting jce/jca Rainbow objects
	/// objects into their org.bouncycastle.crypto counterparts.
	/// </summary>

	public class RainbowKeysToParams
	{
		public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			if (key is BCRainbowPublicKey)
			{
				BCRainbowPublicKey k = (BCRainbowPublicKey)key;

				return new RainbowPublicKeyParameters(k.getDocLength(), k.getCoeffQuadratic(), k.getCoeffSingular(), k.getCoeffScalar());
			}

			throw new InvalidKeyException("can't identify Rainbow public key: " + key.GetType().getName());
		}

		public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
		{
			if (key is BCRainbowPrivateKey)
			{
				BCRainbowPrivateKey k = (BCRainbowPrivateKey)key;
				return new RainbowPrivateKeyParameters(k.getInvA1(), k.getB1(), k.getInvA2(), k.getB2(), k.getVi(), k.getLayers());
			}

			throw new InvalidKeyException("can't identify Rainbow private key.");
		}
	}



}