using org.bouncycastle.asn1.ua;

namespace org.bouncycastle.jcajce.provider.asymmetric.dstu
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using UAObjectIdentifiers = org.bouncycastle.asn1.ua.UAObjectIdentifiers;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using BaseKeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ECPrivateKeySpec = org.bouncycastle.jce.spec.ECPrivateKeySpec;
	using ECPublicKeySpec = org.bouncycastle.jce.spec.ECPublicKeySpec;

	public class KeyFactorySpi : BaseKeyFactorySpi
	{
		public KeyFactorySpi()
		{
		}

		public override KeySpec engineGetKeySpec(Key key, Class spec)
		{
			if (spec.isAssignableFrom(typeof(java.security.spec.ECPublicKeySpec)) && key is ECPublicKey)
			{
				ECPublicKey k = (ECPublicKey)key;
				if (k.getParams() != null)
				{
					return new java.security.spec.ECPublicKeySpec(k.getW(), k.getParams());
				}
				else
				{
					ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

					return new java.security.spec.ECPublicKeySpec(k.getW(), EC5Util.convertSpec(EC5Util.convertCurve(implicitSpec.getCurve(), implicitSpec.getSeed()), implicitSpec));
				}
			}
			else if (spec.isAssignableFrom(typeof(java.security.spec.ECPrivateKeySpec)) && key is ECPrivateKey)
			{
				ECPrivateKey k = (ECPrivateKey)key;

				if (k.getParams() != null)
				{
					return new java.security.spec.ECPrivateKeySpec(k.getS(), k.getParams());
				}
				else
				{
					ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

					return new java.security.spec.ECPrivateKeySpec(k.getS(), EC5Util.convertSpec(EC5Util.convertCurve(implicitSpec.getCurve(), implicitSpec.getSeed()), implicitSpec));
				}
			}
			else if (spec.isAssignableFrom(typeof(ECPublicKeySpec)) && key is ECPublicKey)
			{
				ECPublicKey k = (ECPublicKey)key;
				if (k.getParams() != null)
				{
					return new ECPublicKeySpec(EC5Util.convertPoint(k.getParams(), k.getW(), false), EC5Util.convertSpec(k.getParams(), false));
				}
				else
				{
					ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

					return new ECPublicKeySpec(EC5Util.convertPoint(k.getParams(), k.getW(), false), implicitSpec);
				}
			}
			else if (spec.isAssignableFrom(typeof(ECPrivateKeySpec)) && key is ECPrivateKey)
			{
				ECPrivateKey k = (ECPrivateKey)key;

				if (k.getParams() != null)
				{
					return new ECPrivateKeySpec(k.getS(), EC5Util.convertSpec(k.getParams(), false));
				}
				else
				{
					ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

					return new ECPrivateKeySpec(k.getS(), implicitSpec);
				}
			}

			return base.engineGetKeySpec(key, spec);
		}

		public virtual Key engineTranslateKey(Key key)
		{
			throw new InvalidKeyException("key type unknown");
		}

		public override PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is ECPrivateKeySpec)
			{
				return new BCDSTU4145PrivateKey((ECPrivateKeySpec)keySpec);
			}
			else if (keySpec is java.security.spec.ECPrivateKeySpec)
			{
				return new BCDSTU4145PrivateKey((java.security.spec.ECPrivateKeySpec)keySpec);
			}

			return base.engineGeneratePrivate(keySpec);
		}

		public override PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is ECPublicKeySpec)
			{
				return new BCDSTU4145PublicKey((ECPublicKeySpec)keySpec, BouncyCastleProvider.CONFIGURATION);
			}
			else if (keySpec is java.security.spec.ECPublicKeySpec)
			{
				return new BCDSTU4145PublicKey((java.security.spec.ECPublicKeySpec)keySpec);
			}

			return base.engineGeneratePublic(keySpec);
		}

		public override PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

			if (algOid.Equals(UAObjectIdentifiers_Fields.dstu4145le) || algOid.Equals(UAObjectIdentifiers_Fields.dstu4145be))
			{
				return new BCDSTU4145PrivateKey(keyInfo);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}

		public override PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

			if (algOid.Equals(UAObjectIdentifiers_Fields.dstu4145le) || algOid.Equals(UAObjectIdentifiers_Fields.dstu4145be))
			{
				return new BCDSTU4145PublicKey(keyInfo);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}
	}

}