using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.x509
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	public class KeyFactory : KeyFactorySpi
	{

		public virtual PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is PKCS8EncodedKeySpec)
			{
				try
				{
					PrivateKeyInfo info = PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded());
					PrivateKey key = BouncyCastleProvider.getPrivateKey(info);

					if (key != null)
					{
						return key;
					}

					throw new InvalidKeySpecException("no factory found for OID: " + info.getPrivateKeyAlgorithm().getAlgorithm());
				}
				catch (Exception e)
				{
					throw new InvalidKeySpecException(e.ToString());
				}
			}

			throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.GetType().getName());
		}

		public virtual PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is X509EncodedKeySpec)
			{
				try
				{
					SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(((X509EncodedKeySpec)keySpec).getEncoded());
					PublicKey key = BouncyCastleProvider.getPublicKey(info);

					if (key != null)
					{
						return key;
					}

					throw new InvalidKeySpecException("no factory found for OID: " + info.getAlgorithm().getAlgorithm());
				}
				catch (Exception e)
				{
					throw new InvalidKeySpecException(e.ToString());
				}
			}

			throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.GetType().getName());
		}

		public virtual KeySpec engineGetKeySpec(Key key, Class keySpec)
		{
			if (keySpec.isAssignableFrom(typeof(PKCS8EncodedKeySpec)) && key.getFormat().Equals("PKCS#8"))
			{
				return new PKCS8EncodedKeySpec(key.getEncoded());
			}
			else if (keySpec.isAssignableFrom(typeof(X509EncodedKeySpec)) && key.getFormat().Equals("X.509"))
			{
				return new X509EncodedKeySpec(key.getEncoded());
			}

			throw new InvalidKeySpecException("not implemented yet " + key + " " + keySpec);
		}

		public virtual Key engineTranslateKey(Key key)
		{
			throw new InvalidKeyException("not implemented yet " + key);
		}
	}
}