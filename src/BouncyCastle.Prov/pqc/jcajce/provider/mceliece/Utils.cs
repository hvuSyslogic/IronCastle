using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{
	using DERNull = org.bouncycastle.asn1.DERNull;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Digest = org.bouncycastle.crypto.Digest;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;

	public class Utils
	{
		internal static AlgorithmIdentifier getDigAlgId(string digestName)
		{
			if (digestName.Equals("SHA-1"))
			{
				return new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE);
			}
			if (digestName.Equals("SHA-224"))
			{
				return new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha224, DERNull.INSTANCE);
			}
			if (digestName.Equals("SHA-256"))
			{
				return new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha256, DERNull.INSTANCE);
			}
			if (digestName.Equals("SHA-384"))
			{
				return new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha384, DERNull.INSTANCE);
			}
			if (digestName.Equals("SHA-512"))
			{
				return new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512, DERNull.INSTANCE);
			}

			throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
		}

		internal static Digest getDigest(AlgorithmIdentifier digest)
		{
			if (digest.getAlgorithm().Equals(OIWObjectIdentifiers_Fields.idSHA1))
			{
				return DigestFactory.createSHA1();
			}
			if (digest.getAlgorithm().Equals(NISTObjectIdentifiers_Fields.id_sha224))
			{
				return DigestFactory.createSHA224();
			}
			if (digest.getAlgorithm().Equals(NISTObjectIdentifiers_Fields.id_sha256))
			{
				return DigestFactory.createSHA256();
			}
			if (digest.getAlgorithm().Equals(NISTObjectIdentifiers_Fields.id_sha384))
			{
				return DigestFactory.createSHA384();
			}
			if (digest.getAlgorithm().Equals(NISTObjectIdentifiers_Fields.id_sha512))
			{
				return DigestFactory.createSHA512();
			}
			throw new IllegalArgumentException("unrecognised OID in digest algorithm identifier: " + digest.getAlgorithm());
		}
	}

}