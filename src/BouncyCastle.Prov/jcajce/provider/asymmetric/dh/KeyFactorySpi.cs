using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;

namespace org.bouncycastle.jcajce.provider.asymmetric.dh
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using BaseKeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
	using ExtendedInvalidKeySpecException = org.bouncycastle.jcajce.provider.asymmetric.util.ExtendedInvalidKeySpecException;

	public class KeyFactorySpi : BaseKeyFactorySpi
	{
		public KeyFactorySpi()
		{
		}

		public override KeySpec engineGetKeySpec(Key key, Class spec)
		{
			if (spec.isAssignableFrom(typeof(DHPrivateKeySpec)) && key is DHPrivateKey)
			{
				DHPrivateKey k = (DHPrivateKey)key;

				return new DHPrivateKeySpec(k.getX(), k.getParams().getP(), k.getParams().getG());
			}
			else if (spec.isAssignableFrom(typeof(DHPublicKeySpec)) && key is DHPublicKey)
			{
				DHPublicKey k = (DHPublicKey)key;

				return new DHPublicKeySpec(k.getY(), k.getParams().getP(), k.getParams().getG());
			}

			return base.engineGetKeySpec(key, spec);
		}

		public virtual Key engineTranslateKey(Key key)
		{
			if (key is DHPublicKey)
			{
				return new BCDHPublicKey((DHPublicKey)key);
			}
			else if (key is DHPrivateKey)
			{
				return new BCDHPrivateKey((DHPrivateKey)key);
			}

			throw new InvalidKeyException("key type unknown");
		}

		public override PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is DHPrivateKeySpec)
			{
				return new BCDHPrivateKey((DHPrivateKeySpec)keySpec);
			}

			return base.engineGeneratePrivate(keySpec);
		}

		public override PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is DHPublicKeySpec)
			{
				try
				{
					return new BCDHPublicKey((DHPublicKeySpec)keySpec);
				}
				catch (IllegalArgumentException e)
				{
					throw new ExtendedInvalidKeySpecException(e.getMessage(), e);
				}
			}

			return base.engineGeneratePublic(keySpec);
		}

		public override PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

			if (algOid.Equals(PKCSObjectIdentifiers_Fields.dhKeyAgreement))
			{
				return new BCDHPrivateKey(keyInfo);
			}
			else if (algOid.Equals(X9ObjectIdentifiers_Fields.dhpublicnumber))
			{
				return new BCDHPrivateKey(keyInfo);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}

		public override PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

			if (algOid.Equals(PKCSObjectIdentifiers_Fields.dhKeyAgreement))
			{
				return new BCDHPublicKey(keyInfo);
			}
			else if (algOid.Equals(X9ObjectIdentifiers_Fields.dhpublicnumber))
			{
				return new BCDHPublicKey(keyInfo);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}
	}

}