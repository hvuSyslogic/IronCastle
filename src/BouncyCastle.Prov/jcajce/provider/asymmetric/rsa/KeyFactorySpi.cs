using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using RSAPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using OpenSSHPrivateKeyUtil = org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
	using OpenSSHPublicKeyUtil = org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
	using BaseKeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
	using ExtendedInvalidKeySpecException = org.bouncycastle.jcajce.provider.asymmetric.util.ExtendedInvalidKeySpecException;
	using OpenSSHPrivateKeySpec = org.bouncycastle.jce.spec.OpenSSHPrivateKeySpec;
	using OpenSSHPublicKeySpec = org.bouncycastle.jce.spec.OpenSSHPublicKeySpec;

	public class KeyFactorySpi : BaseKeyFactorySpi
	{
		public KeyFactorySpi()
		{
		}

		public override KeySpec engineGetKeySpec(Key key, Class spec)
		{
			if (spec.isAssignableFrom(typeof(RSAPublicKeySpec)) && key is RSAPublicKey)
			{
				RSAPublicKey k = (RSAPublicKey)key;

				return new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent());
			}
			else if (spec.isAssignableFrom(typeof(RSAPrivateKeySpec)) && key is java.security.interfaces.RSAPrivateKey)
			{
				java.security.interfaces.RSAPrivateKey k = (java.security.interfaces.RSAPrivateKey)key;

				return new RSAPrivateKeySpec(k.getModulus(), k.getPrivateExponent());
			}
			else if (spec.isAssignableFrom(typeof(RSAPrivateCrtKeySpec)) && key is RSAPrivateCrtKey)
			{
				RSAPrivateCrtKey k = (RSAPrivateCrtKey)key;

				return new RSAPrivateCrtKeySpec(k.getModulus(), k.getPublicExponent(), k.getPrivateExponent(), k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient());
			}
			else if (spec.isAssignableFrom(typeof(OpenSSHPublicKeySpec)) && key is RSAPublicKey)
			{
				try
				{
					return new OpenSSHPublicKeySpec(OpenSSHPublicKeyUtil.encodePublicKey(new RSAKeyParameters(false, ((RSAPublicKey)key).getModulus(), ((RSAPublicKey)key).getPublicExponent())
					   ));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("unable to produce encoding: " + e.Message);
				}
			}
			else if (spec.isAssignableFrom(typeof(OpenSSHPrivateKeySpec)) && key is RSAPrivateCrtKey)
			{
				try
				{
					return new OpenSSHPrivateKeySpec(OpenSSHPrivateKeyUtil.encodePrivateKey(new RSAPrivateCrtKeyParameters(((RSAPrivateCrtKey)key).getModulus(), ((RSAPrivateCrtKey)key).getPublicExponent(), ((RSAPrivateCrtKey)key).getPrivateExponent(), ((RSAPrivateCrtKey)key).getPrimeP(), ((RSAPrivateCrtKey)key).getPrimeQ(), ((RSAPrivateCrtKey)key).getPrimeExponentP(), ((RSAPrivateCrtKey)key).getPrimeExponentQ(), ((RSAPrivateCrtKey)key).getCrtCoefficient())));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("unable to produce encoding: " + e.Message);
				}
			}

			return base.engineGetKeySpec(key, spec);
		}

		public virtual Key engineTranslateKey(Key key)
		{
			if (key is RSAPublicKey)
			{
				return new BCRSAPublicKey((RSAPublicKey)key);
			}
			else if (key is RSAPrivateCrtKey)
			{
				return new BCRSAPrivateCrtKey((RSAPrivateCrtKey)key);
			}
			else if (key is java.security.interfaces.RSAPrivateKey)
			{
				return new BCRSAPrivateKey((java.security.interfaces.RSAPrivateKey)key);
			}

			throw new InvalidKeyException("key type unknown");
		}

		public override PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is PKCS8EncodedKeySpec)
			{
				try
				{
					return generatePrivate(PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded()));
				}
				catch (Exception e)
				{
					//
					// in case it's just a RSAPrivateKey object... -- openSSL produces these
					//
					try
					{
						return new BCRSAPrivateCrtKey(RSAPrivateKey.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded()));
					}
					catch (Exception)
					{
						throw new ExtendedInvalidKeySpecException("unable to process key spec: " + e.ToString(), e);
					}
				}
			}
			else if (keySpec is RSAPrivateCrtKeySpec)
			{
				return new BCRSAPrivateCrtKey((RSAPrivateCrtKeySpec)keySpec);
			}
			else if (keySpec is RSAPrivateKeySpec)
			{
				return new BCRSAPrivateKey((RSAPrivateKeySpec)keySpec);
			}
			else if (keySpec is OpenSSHPrivateKeySpec)
			{
				CipherParameters parameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(((OpenSSHPrivateKeySpec)keySpec).getEncoded());

				if (parameters is RSAPrivateCrtKeyParameters)
				{
					return new BCRSAPrivateCrtKey((RSAPrivateCrtKeyParameters)parameters);
				}

				throw new InvalidKeySpecException("open SSH public key is not RSA private key");
			}

			throw new InvalidKeySpecException("unknown KeySpec type: " + keySpec.GetType().getName());
		}

		public override PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is RSAPublicKeySpec)
			{
				return new BCRSAPublicKey((RSAPublicKeySpec)keySpec);
			}
			else if (keySpec is OpenSSHPublicKeySpec)
			{

				CipherParameters parameters = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)keySpec).getEncoded());
				if (parameters is RSAKeyParameters)
				{
					return new BCRSAPublicKey((RSAKeyParameters)parameters);
				}

				throw new InvalidKeySpecException("Open SSH public key is not RSA public key");

			}

			return base.engineGeneratePublic(keySpec);
		}

		public override PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

			if (RSAUtil.isRsaOid(algOid))
			{
				RSAPrivateKey rsaPrivKey = RSAPrivateKey.getInstance(keyInfo.parsePrivateKey());

				if (rsaPrivKey.getCoefficient().intValue() == 0)
				{
					return new BCRSAPrivateKey(rsaPrivKey);
				}
				else
				{
					return new BCRSAPrivateCrtKey(keyInfo);
				}
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}

		public override PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

			if (RSAUtil.isRsaOid(algOid))
			{
				return new BCRSAPublicKey(keyInfo);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}
	}

}