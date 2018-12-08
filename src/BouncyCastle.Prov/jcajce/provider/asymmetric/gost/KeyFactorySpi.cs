using org.bouncycastle.asn1.cryptopro;

namespace org.bouncycastle.jcajce.provider.asymmetric.gost
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using BaseKeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
	using GOST3410PrivateKey = org.bouncycastle.jce.interfaces.GOST3410PrivateKey;
	using GOST3410PublicKey = org.bouncycastle.jce.interfaces.GOST3410PublicKey;
	using GOST3410PrivateKeySpec = org.bouncycastle.jce.spec.GOST3410PrivateKeySpec;
	using GOST3410PublicKeyParameterSetSpec = org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;
	using GOST3410PublicKeySpec = org.bouncycastle.jce.spec.GOST3410PublicKeySpec;

	public class KeyFactorySpi : BaseKeyFactorySpi
	{
		public KeyFactorySpi()
		{
		}

		public override KeySpec engineGetKeySpec(Key key, Class spec)
		{
			if (spec.isAssignableFrom(typeof(GOST3410PublicKeySpec)) && key is GOST3410PublicKey)
			{
				GOST3410PublicKey k = (GOST3410PublicKey)key;
				GOST3410PublicKeyParameterSetSpec parameters = k.getParameters().getPublicKeyParameters();

				return new GOST3410PublicKeySpec(k.getY(), parameters.getP(), parameters.getQ(), parameters.getA());
			}
			else if (spec.isAssignableFrom(typeof(GOST3410PrivateKeySpec)) && key is GOST3410PrivateKey)
			{
				GOST3410PrivateKey k = (GOST3410PrivateKey)key;
				GOST3410PublicKeyParameterSetSpec parameters = k.getParameters().getPublicKeyParameters();

				return new GOST3410PrivateKeySpec(k.getX(), parameters.getP(), parameters.getQ(), parameters.getA());
			}

			return base.engineGetKeySpec(key, spec);
		}

		public virtual Key engineTranslateKey(Key key)
		{
			if (key is GOST3410PublicKey)
			{
				return new BCGOST3410PublicKey((GOST3410PublicKey)key);
			}
			else if (key is GOST3410PrivateKey)
			{
				return new BCGOST3410PrivateKey((GOST3410PrivateKey)key);
			}

			throw new InvalidKeyException("key type unknown");
		}

		public override PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is GOST3410PrivateKeySpec)
			{
				return new BCGOST3410PrivateKey((GOST3410PrivateKeySpec)keySpec);
			}

			return base.engineGeneratePrivate(keySpec);
		}

		public override PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is GOST3410PublicKeySpec)
			{
				return new BCGOST3410PublicKey((GOST3410PublicKeySpec)keySpec);
			}

			return base.engineGeneratePublic(keySpec);
		}

		public override PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

			if (algOid.Equals(CryptoProObjectIdentifiers_Fields.gostR3410_94))
			{
				return new BCGOST3410PrivateKey(keyInfo);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}

		public override PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

			if (algOid.Equals(CryptoProObjectIdentifiers_Fields.gostR3410_94))
			{
				return new BCGOST3410PublicKey(keyInfo);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}
	}

}