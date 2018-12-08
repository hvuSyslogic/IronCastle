namespace org.bouncycastle.jcajce.provider.asymmetric.util
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using GOST3410Parameters = org.bouncycastle.crypto.@params.GOST3410Parameters;
	using GOST3410PrivateKeyParameters = org.bouncycastle.crypto.@params.GOST3410PrivateKeyParameters;
	using GOST3410PublicKeyParameters = org.bouncycastle.crypto.@params.GOST3410PublicKeyParameters;
	using GOST3410PrivateKey = org.bouncycastle.jce.interfaces.GOST3410PrivateKey;
	using GOST3410PublicKey = org.bouncycastle.jce.interfaces.GOST3410PublicKey;
	using GOST3410PublicKeyParameterSetSpec = org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

	/// <summary>
	/// utility class for converting jce/jca GOST3410-94 objects
	/// objects into their org.bouncycastle.crypto counterparts.
	/// </summary>
	public class GOST3410Util
	{
		public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			if (key is GOST3410PublicKey)
			{
				GOST3410PublicKey k = (GOST3410PublicKey)key;
				GOST3410PublicKeyParameterSetSpec p = k.getParameters().getPublicKeyParameters();

				return new GOST3410PublicKeyParameters(k.getY(), new GOST3410Parameters(p.getP(), p.getQ(), p.getA()));
			}

			throw new InvalidKeyException("can't identify GOST3410 public key: " + key.GetType().getName());
		}

		public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
		{
			if (key is GOST3410PrivateKey)
			{
				GOST3410PrivateKey k = (GOST3410PrivateKey)key;
				GOST3410PublicKeyParameterSetSpec p = k.getParameters().getPublicKeyParameters();

				return new GOST3410PrivateKeyParameters(k.getX(), new GOST3410Parameters(p.getP(), p.getQ(), p.getA()));
			}

			throw new InvalidKeyException("can't identify GOST3410 private key.");
		}
	}

}