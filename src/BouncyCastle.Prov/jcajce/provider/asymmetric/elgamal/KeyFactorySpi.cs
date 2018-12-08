using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.jcajce.provider.asymmetric.elgamal
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using BaseKeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
	using ElGamalPrivateKey = org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
	using ElGamalPublicKey = org.bouncycastle.jce.interfaces.ElGamalPublicKey;
	using ElGamalPrivateKeySpec = org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
	using ElGamalPublicKeySpec = org.bouncycastle.jce.spec.ElGamalPublicKeySpec;

	public class KeyFactorySpi : BaseKeyFactorySpi
	{
		public KeyFactorySpi()
		{
		}

		public override PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is ElGamalPrivateKeySpec)
			{
				return new BCElGamalPrivateKey((ElGamalPrivateKeySpec)keySpec);
			}
			else if (keySpec is DHPrivateKeySpec)
			{
				return new BCElGamalPrivateKey((DHPrivateKeySpec)keySpec);
			}

			return base.engineGeneratePrivate(keySpec);
		}

		public override PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is ElGamalPublicKeySpec)
			{
				return new BCElGamalPublicKey((ElGamalPublicKeySpec)keySpec);
			}
			else if (keySpec is DHPublicKeySpec)
			{
				return new BCElGamalPublicKey((DHPublicKeySpec)keySpec);
			}
			return base.engineGeneratePublic(keySpec);
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
				return new BCElGamalPublicKey((DHPublicKey)key);
			}
			else if (key is DHPrivateKey)
			{
				return new BCElGamalPrivateKey((DHPrivateKey)key);
			}
			else if (key is ElGamalPublicKey)
			{
				return new BCElGamalPublicKey((ElGamalPublicKey)key);
			}
			else if (key is ElGamalPrivateKey)
			{
				return new BCElGamalPrivateKey((ElGamalPrivateKey)key);
			}

			throw new InvalidKeyException("key type unknown");
		}

		public override PrivateKey generatePrivate(PrivateKeyInfo info)
		{
			ASN1ObjectIdentifier algOid = info.getPrivateKeyAlgorithm().getAlgorithm();

			if (algOid.Equals(PKCSObjectIdentifiers_Fields.dhKeyAgreement))
			{
				return new BCElGamalPrivateKey(info);
			}
			else if (algOid.Equals(X9ObjectIdentifiers_Fields.dhpublicnumber))
			{
				return new BCElGamalPrivateKey(info);
			}
			else if (algOid.Equals(OIWObjectIdentifiers_Fields.elGamalAlgorithm))
			{
				return new BCElGamalPrivateKey(info);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}

		public override PublicKey generatePublic(SubjectPublicKeyInfo info)
		{
			ASN1ObjectIdentifier algOid = info.getAlgorithm().getAlgorithm();

			if (algOid.Equals(PKCSObjectIdentifiers_Fields.dhKeyAgreement))
			{
				return new BCElGamalPublicKey(info);
			}
			else if (algOid.Equals(X9ObjectIdentifiers_Fields.dhpublicnumber))
			{
				return new BCElGamalPublicKey(info);
			}
			else if (algOid.Equals(OIWObjectIdentifiers_Fields.elGamalAlgorithm))
			{
				return new BCElGamalPublicKey(info);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}
	}

}