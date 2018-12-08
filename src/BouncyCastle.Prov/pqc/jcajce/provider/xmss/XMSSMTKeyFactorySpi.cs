using System;

namespace org.bouncycastle.pqc.jcajce.provider.xmss
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

	public class XMSSMTKeyFactorySpi : KeyFactorySpi, AsymmetricKeyInfoConverter
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

			throw new InvalidKeySpecException("unsupported key specification: " + keySpec.GetType() + ".");
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

			throw new InvalidKeySpecException("unknown key specification: " + keySpec + ".");
		}

		public KeySpec engineGetKeySpec(Key key, Class keySpec)
		{
			if (key is BCXMSSMTPrivateKey)
			{
				if (typeof(PKCS8EncodedKeySpec).isAssignableFrom(keySpec))
				{
					return new PKCS8EncodedKeySpec(key.getEncoded());
				}
			}
			else if (key is BCXMSSMTPublicKey)
			{
				if (typeof(X509EncodedKeySpec).isAssignableFrom(keySpec))
				{
					return new X509EncodedKeySpec(key.getEncoded());
				}
			}
			else
			{
				throw new InvalidKeySpecException("unsupported key type: " + key.GetType() + ".");
			}

			throw new InvalidKeySpecException("unknown key specification: " + keySpec + ".");
		}

		public Key engineTranslateKey(Key key)
		{
			if (key is BCXMSSMTPrivateKey || key is BCXMSSMTPublicKey)
			{
				return key;
			}

			throw new InvalidKeyException("unsupported key type");
		}

		public virtual PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
		{
			return new BCXMSSMTPrivateKey(keyInfo);
		}

		public virtual PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
		{
			return new BCXMSSMTPublicKey(keyInfo);
		}
	}

}