using System;

namespace org.bouncycastle.pqc.jcajce.provider.sphincs
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

	public class Sphincs256KeyFactorySpi : KeyFactorySpi, AsymmetricKeyInfoConverter
	{
		public virtual PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is PKCS8EncodedKeySpec)
			{
				// get the DER-encoded Key according to PKCS#8 from the spec
				byte[] encKey = ((PKCS8EncodedKeySpec)keySpec).getEncoded();

				try
				{
					return generatePrivate(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey)));
				}
				catch (Exception e)
				{
					throw new InvalidKeySpecException(e.ToString());
				}
			}

			throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.GetType() + ".");
		}

		public virtual PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is X509EncodedKeySpec)
			{
				// get the DER-encoded Key according to X.509 from the spec
				byte[] encKey = ((X509EncodedKeySpec)keySpec).getEncoded();

				// decode the SubjectPublicKeyInfo data structure to the pki object
				try
				{
					return generatePublic(SubjectPublicKeyInfo.getInstance(encKey));
				}
				catch (Exception e)
				{
					throw new InvalidKeySpecException(e.ToString());
				}
			}

			throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
		}

		public KeySpec engineGetKeySpec(Key key, Class keySpec)
		{
			if (key is BCSphincs256PrivateKey)
			{
				if (typeof(PKCS8EncodedKeySpec).isAssignableFrom(keySpec))
				{
					return new PKCS8EncodedKeySpec(key.getEncoded());
				}
			}
			else if (key is BCSphincs256PublicKey)
			{
				if (typeof(X509EncodedKeySpec).isAssignableFrom(keySpec))
				{
					return new X509EncodedKeySpec(key.getEncoded());
				}
			}
			else
			{
				throw new InvalidKeySpecException("Unsupported key type: " + key.GetType() + ".");
			}

			throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
		}

		public Key engineTranslateKey(Key key)
		{
			if (key is BCSphincs256PrivateKey || key is BCSphincs256PublicKey)
			{
				return key;
			}

			throw new InvalidKeyException("Unsupported key type");
		}

		public virtual PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
		{
			return new BCSphincs256PrivateKey(keyInfo);
		}

		public virtual PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
		{
			return new BCSphincs256PublicKey(keyInfo);
		}
	}

}