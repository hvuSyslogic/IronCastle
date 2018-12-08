using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.util
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

	public abstract class BaseKeyFactorySpi : java.security.KeyFactorySpi, AsymmetricKeyInfoConverter
	{
		public abstract PublicKey generatePublic(SubjectPublicKeyInfo keyInfo);
		public abstract PrivateKey generatePrivate(PrivateKeyInfo keyInfo);
		public virtual PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is PKCS8EncodedKeySpec)
			{
				try
				{
					return generatePrivate(PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded()));
				}
				catch (Exception e)
				{
					throw new InvalidKeySpecException("encoded key spec not recognized: " + e.Message);
				}
			}
			else
			{
				throw new InvalidKeySpecException("key spec not recognized");
			}
		}

		public virtual PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is X509EncodedKeySpec)
			{
				try
				{
					return generatePublic(SubjectPublicKeyInfo.getInstance(((X509EncodedKeySpec)keySpec).getEncoded()));
				}
				catch (Exception e)
				{
					throw new InvalidKeySpecException("encoded key spec not recognized: " + e.Message);
				}
			}
			else
			{
				throw new InvalidKeySpecException("key spec not recognized");
			}
		}

		public virtual KeySpec engineGetKeySpec(Key key, Class spec)
		{
			if (spec.isAssignableFrom(typeof(PKCS8EncodedKeySpec)) && key.getFormat().Equals("PKCS#8"))
			{
				return new PKCS8EncodedKeySpec(key.getEncoded());
			}
			else if (spec.isAssignableFrom(typeof(X509EncodedKeySpec)) && key.getFormat().Equals("X.509"))
			{
				return new X509EncodedKeySpec(key.getEncoded());
			}

			throw new InvalidKeySpecException("not implemented yet " + key + " " + spec);
		}
	}

}