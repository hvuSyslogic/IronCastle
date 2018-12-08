namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using McEliecePrivateKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;

	/// <summary>
	/// utility class for converting jce/jca McEliece objects
	/// objects into their org.bouncycastle.crypto counterparts.
	/// </summary>
	public class McElieceKeysToParams
	{


		public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			if (key is BCMcEliecePublicKey)
			{
				BCMcEliecePublicKey k = (BCMcEliecePublicKey)key;

				return k.getKeyParams();
			}

			throw new InvalidKeyException("can't identify McEliece public key: " + key.GetType().getName());
		}


		public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
		{
			if (key is BCMcEliecePrivateKey)
			{
				BCMcEliecePrivateKey k = (BCMcEliecePrivateKey)key;
				return new McEliecePrivateKeyParameters(k.getN(), k.getK(), k.getField(), k.getGoppaPoly(), k.getP1(), k.getP2(), k.getSInv());
			}

			throw new InvalidKeyException("can't identify McEliece private key.");
		}
	}

}