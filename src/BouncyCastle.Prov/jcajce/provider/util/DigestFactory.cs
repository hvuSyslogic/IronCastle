using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.crypto.util;

namespace org.bouncycastle.jcajce.provider.util
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Digest = org.bouncycastle.crypto.Digest;
	using Strings = org.bouncycastle.util.Strings;

	public class DigestFactory
	{
		private static Set md5 = new HashSet();
		private static Set sha1 = new HashSet();
		private static Set sha224 = new HashSet();
		private static Set sha256 = new HashSet();
		private static Set sha384 = new HashSet();
		private static Set sha512 = new HashSet();
		private static Set sha512_224 = new HashSet();
		private static Set sha512_256 = new HashSet();
		private static Set sha3_224 = new HashSet();
		private static Set sha3_256 = new HashSet();
		private static Set sha3_384 = new HashSet();
		private static Set sha3_512 = new HashSet();

		private static Map oids = new HashMap();

		static DigestFactory()
		{
			md5.add("MD5");
			md5.add(PKCSObjectIdentifiers_Fields.md5.getId());

			sha1.add("SHA1");
			sha1.add("SHA-1");
			sha1.add(OIWObjectIdentifiers_Fields.idSHA1.getId());

			sha224.add("SHA224");
			sha224.add("SHA-224");
			sha224.add(NISTObjectIdentifiers_Fields.id_sha224.getId());

			sha256.add("SHA256");
			sha256.add("SHA-256");
			sha256.add(NISTObjectIdentifiers_Fields.id_sha256.getId());

			sha384.add("SHA384");
			sha384.add("SHA-384");
			sha384.add(NISTObjectIdentifiers_Fields.id_sha384.getId());

			sha512.add("SHA512");
			sha512.add("SHA-512");
			sha512.add(NISTObjectIdentifiers_Fields.id_sha512.getId());

			sha512_224.add("SHA512(224)");
			sha512_224.add("SHA-512(224)");
			sha512_224.add(NISTObjectIdentifiers_Fields.id_sha512_224.getId());

			sha512_256.add("SHA512(256)");
			sha512_256.add("SHA-512(256)");
			sha512_256.add(NISTObjectIdentifiers_Fields.id_sha512_256.getId());

			sha3_224.add("SHA3-224");
			sha3_224.add(NISTObjectIdentifiers_Fields.id_sha3_224.getId());

			sha3_256.add("SHA3-256");
			sha3_256.add(NISTObjectIdentifiers_Fields.id_sha3_256.getId());

			sha3_384.add("SHA3-384");
			sha3_384.add(NISTObjectIdentifiers_Fields.id_sha3_384.getId());

			sha3_512.add("SHA3-512");
			sha3_512.add(NISTObjectIdentifiers_Fields.id_sha3_512.getId());

			oids.put("MD5", PKCSObjectIdentifiers_Fields.md5);
			oids.put(PKCSObjectIdentifiers_Fields.md5.getId(), PKCSObjectIdentifiers_Fields.md5);

			oids.put("SHA1", OIWObjectIdentifiers_Fields.idSHA1);
			oids.put("SHA-1", OIWObjectIdentifiers_Fields.idSHA1);
			oids.put(OIWObjectIdentifiers_Fields.idSHA1.getId(), OIWObjectIdentifiers_Fields.idSHA1);

			oids.put("SHA224", NISTObjectIdentifiers_Fields.id_sha224);
			oids.put("SHA-224", NISTObjectIdentifiers_Fields.id_sha224);
			oids.put(NISTObjectIdentifiers_Fields.id_sha224.getId(), NISTObjectIdentifiers_Fields.id_sha224);

			oids.put("SHA256", NISTObjectIdentifiers_Fields.id_sha256);
			oids.put("SHA-256", NISTObjectIdentifiers_Fields.id_sha256);
			oids.put(NISTObjectIdentifiers_Fields.id_sha256.getId(), NISTObjectIdentifiers_Fields.id_sha256);

			oids.put("SHA384", NISTObjectIdentifiers_Fields.id_sha384);
			oids.put("SHA-384", NISTObjectIdentifiers_Fields.id_sha384);
			oids.put(NISTObjectIdentifiers_Fields.id_sha384.getId(), NISTObjectIdentifiers_Fields.id_sha384);

			oids.put("SHA512", NISTObjectIdentifiers_Fields.id_sha512);
			oids.put("SHA-512", NISTObjectIdentifiers_Fields.id_sha512);
			oids.put(NISTObjectIdentifiers_Fields.id_sha512.getId(), NISTObjectIdentifiers_Fields.id_sha512);

			oids.put("SHA512(224)", NISTObjectIdentifiers_Fields.id_sha512_224);
			oids.put("SHA-512(224)", NISTObjectIdentifiers_Fields.id_sha512_224);
			oids.put(NISTObjectIdentifiers_Fields.id_sha512_224.getId(), NISTObjectIdentifiers_Fields.id_sha512_224);

			oids.put("SHA512(256)", NISTObjectIdentifiers_Fields.id_sha512_256);
			oids.put("SHA-512(256)", NISTObjectIdentifiers_Fields.id_sha512_256);
			oids.put(NISTObjectIdentifiers_Fields.id_sha512_256.getId(), NISTObjectIdentifiers_Fields.id_sha512_256);

			oids.put("SHA3-224", NISTObjectIdentifiers_Fields.id_sha3_224);
			oids.put(NISTObjectIdentifiers_Fields.id_sha3_224.getId(), NISTObjectIdentifiers_Fields.id_sha3_224);

			oids.put("SHA3-256", NISTObjectIdentifiers_Fields.id_sha3_256);
			oids.put(NISTObjectIdentifiers_Fields.id_sha3_256.getId(), NISTObjectIdentifiers_Fields.id_sha3_256);

			oids.put("SHA3-384", NISTObjectIdentifiers_Fields.id_sha3_384);
			oids.put(NISTObjectIdentifiers_Fields.id_sha3_384.getId(), NISTObjectIdentifiers_Fields.id_sha3_384);

			oids.put("SHA3-512", NISTObjectIdentifiers_Fields.id_sha3_512);
			oids.put(NISTObjectIdentifiers_Fields.id_sha3_512.getId(), NISTObjectIdentifiers_Fields.id_sha3_512);
		}

		public static Digest getDigest(string digestName)
		{
			digestName = Strings.toUpperCase(digestName);

			if (sha1.contains(digestName))
			{
				return DigestFactory.createSHA1();
			}
			if (md5.contains(digestName))
			{
				return DigestFactory.createMD5();
			}
			if (sha224.contains(digestName))
			{
				return DigestFactory.createSHA224();
			}
			if (sha256.contains(digestName))
			{
				return DigestFactory.createSHA256();
			}
			if (sha384.contains(digestName))
			{
				return DigestFactory.createSHA384();
			}
			if (sha512.contains(digestName))
			{
				return DigestFactory.createSHA512();
			}
			if (sha512_224.contains(digestName))
			{
				return DigestFactory.createSHA512_224();
			}
			if (sha512_256.contains(digestName))
			{
				return DigestFactory.createSHA512_256();
			}

			if (sha3_224.contains(digestName))
			{
				return DigestFactory.createSHA3_224();
			}
			if (sha3_256.contains(digestName))
			{
				return DigestFactory.createSHA3_256();
			}
			if (sha3_384.contains(digestName))
			{
				return DigestFactory.createSHA3_384();
			}
			if (sha3_512.contains(digestName))
			{
				return DigestFactory.createSHA3_512();
			}

			return null;
		}

		public static bool isSameDigest(string digest1, string digest2)
		{
			return (sha1.contains(digest1) && sha1.contains(digest2)) || (sha224.contains(digest1) && sha224.contains(digest2)) || (sha256.contains(digest1) && sha256.contains(digest2)) || (sha384.contains(digest1) && sha384.contains(digest2)) || (sha512.contains(digest1) && sha512.contains(digest2)) || (sha512_224.contains(digest1) && sha512_224.contains(digest2)) || (sha512_256.contains(digest1) && sha512_256.contains(digest2)) || (sha3_224.contains(digest1) && sha3_224.contains(digest2)) || (sha3_256.contains(digest1) && sha3_256.contains(digest2)) || (sha3_384.contains(digest1) && sha3_384.contains(digest2)) || (sha3_512.contains(digest1) && sha3_512.contains(digest2)) || (md5.contains(digest1) && md5.contains(digest2));
		}

		public static ASN1ObjectIdentifier getOID(string digestName)
		{
			return (ASN1ObjectIdentifier)oids.get(digestName);
		}
	}

}