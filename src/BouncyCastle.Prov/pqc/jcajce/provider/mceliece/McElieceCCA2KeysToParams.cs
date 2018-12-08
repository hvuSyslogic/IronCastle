namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	/// <summary>
	/// utility class for converting jce/jca McElieceCCA2 objects
	/// objects into their org.bouncycastle.crypto counterparts.
	/// </summary>
	public class McElieceCCA2KeysToParams
	{


		public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			if (key is BCMcElieceCCA2PublicKey)
			{
				BCMcElieceCCA2PublicKey k = (BCMcElieceCCA2PublicKey)key;

				return k.getKeyParams();
			}

			throw new InvalidKeyException("can't identify McElieceCCA2 public key: " + key.GetType().getName());
		}


		public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
		{
			if (key is BCMcElieceCCA2PrivateKey)
			{
				BCMcElieceCCA2PrivateKey k = (BCMcElieceCCA2PrivateKey)key;

				return k.getKeyParams();
			}

			throw new InvalidKeyException("can't identify McElieceCCA2 private key.");
		}
	}

}