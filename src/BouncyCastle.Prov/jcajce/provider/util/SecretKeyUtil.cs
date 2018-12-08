using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.ntt;

namespace org.bouncycastle.jcajce.provider.util
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Integers = org.bouncycastle.util.Integers;

	public class SecretKeyUtil
	{
		private static Map keySizes = new HashMap();

		static SecretKeyUtil()
		{
			keySizes.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId(), Integers.valueOf(192));

			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_CBC, Integers.valueOf(128));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_CBC, Integers.valueOf(192));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_CBC, Integers.valueOf(256));

			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia128_cbc, Integers.valueOf(128));
			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia192_cbc, Integers.valueOf(192));
			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia256_cbc, Integers.valueOf(256));
		}

		public static int getKeySize(ASN1ObjectIdentifier oid)
		{
			int? size = (int?)keySizes.get(oid);

			if (size != null)
			{
				return size.Value;
			}

			return -1;
		}
	}

}