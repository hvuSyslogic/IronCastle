using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;

using System;

namespace org.bouncycastle.openssl
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Integers = org.bouncycastle.util.Integers;

	public sealed class PEMUtilities
	{
		private static readonly Map KEYSIZES = new HashMap();
		private static readonly Set PKCS5_SCHEME_1 = new HashSet();
		private static readonly Set PKCS5_SCHEME_2 = new HashSet();

		static PEMUtilities()
		{
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithMD2AndDES_CBC);
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithMD2AndRC2_CBC);
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithMD5AndDES_CBC);
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithMD5AndRC2_CBC);
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithSHA1AndDES_CBC);
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithSHA1AndRC2_CBC);

			PKCS5_SCHEME_2.add(PKCSObjectIdentifiers_Fields.id_PBES2);
			PKCS5_SCHEME_2.add(PKCSObjectIdentifiers_Fields.des_EDE3_CBC);
			PKCS5_SCHEME_2.add(NISTObjectIdentifiers_Fields.id_aes128_CBC);
			PKCS5_SCHEME_2.add(NISTObjectIdentifiers_Fields.id_aes192_CBC);
			PKCS5_SCHEME_2.add(NISTObjectIdentifiers_Fields.id_aes256_CBC);

			KEYSIZES.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId(), Integers.valueOf(192));
			KEYSIZES.put(NISTObjectIdentifiers_Fields.id_aes128_CBC.getId(), Integers.valueOf(128));
			KEYSIZES.put(NISTObjectIdentifiers_Fields.id_aes192_CBC.getId(), Integers.valueOf(192));
			KEYSIZES.put(NISTObjectIdentifiers_Fields.id_aes256_CBC.getId(), Integers.valueOf(256));
		}

		internal static int getKeySize(string algorithm)
		{
			if (!KEYSIZES.containsKey(algorithm))
			{
				throw new IllegalStateException("no key size for algorithm: " + algorithm);
			}

			return ((int?)KEYSIZES.get(algorithm)).Value;
		}

		internal static bool isPKCS5Scheme1(ASN1ObjectIdentifier algOid)
		{
			return PKCS5_SCHEME_1.contains(algOid);
		}

		public static bool isPKCS5Scheme2(ASN1ObjectIdentifier algOid)
		{
			return PKCS5_SCHEME_2.contains(algOid);
		}

		public static bool isPKCS12(ASN1ObjectIdentifier algOid)
		{
			return algOid.getId().StartsWith(PKCSObjectIdentifiers_Fields.pkcs_12PbeIds.getId(), StringComparison.Ordinal);
		}
	}

}