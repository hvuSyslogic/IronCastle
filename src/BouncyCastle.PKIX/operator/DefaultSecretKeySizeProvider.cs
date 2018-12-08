using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.ntt;
using org.bouncycastle.asn1.kisa;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.cryptopro;

namespace org.bouncycastle.@operator
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using KISAObjectIdentifiers = org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Integers = org.bouncycastle.util.Integers;

	public class DefaultSecretKeySizeProvider : SecretKeySizeProvider
	{
		public static readonly SecretKeySizeProvider INSTANCE = new DefaultSecretKeySizeProvider();

		private static readonly Map KEY_SIZES;

		static DefaultSecretKeySizeProvider()
		{
			Map keySizes = new HashMap();

			keySizes.put(new ASN1ObjectIdentifier("1.2.840.113533.7.66.10"), Integers.valueOf(128));

			keySizes.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC, Integers.valueOf(192));
			keySizes.put(PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap, Integers.valueOf(192));
			keySizes.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC, Integers.valueOf(192));

			keySizes.put(PKCSObjectIdentifiers_Fields.pbeWithSHA1AndDES_CBC, Integers.valueOf(64));
			keySizes.put(PKCSObjectIdentifiers_Fields.pbeWithMD5AndDES_CBC, Integers.valueOf(64));

			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_CBC, Integers.valueOf(128));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_CBC, Integers.valueOf(192));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_CBC, Integers.valueOf(256));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_GCM, Integers.valueOf(128));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_GCM, Integers.valueOf(192));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_GCM, Integers.valueOf(256));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_CCM, Integers.valueOf(128));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_CCM, Integers.valueOf(192));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_CCM, Integers.valueOf(256));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_wrap, Integers.valueOf(128));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_wrap, Integers.valueOf(192));
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_wrap, Integers.valueOf(256));

			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia128_cbc, Integers.valueOf(128));
			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia192_cbc, Integers.valueOf(192));
			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia256_cbc, Integers.valueOf(256));
			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia128_wrap, Integers.valueOf(128));
			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia192_wrap, Integers.valueOf(192));
			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia256_wrap, Integers.valueOf(256));

			keySizes.put(KISAObjectIdentifiers_Fields.id_seedCBC, Integers.valueOf(128));

			keySizes.put(OIWObjectIdentifiers_Fields.desCBC, Integers.valueOf(64));

			keySizes.put(CryptoProObjectIdentifiers_Fields.gostR28147_gcfb, Integers.valueOf(256));

			KEY_SIZES = Collections.unmodifiableMap(keySizes);
		}

		public virtual int getKeySize(AlgorithmIdentifier algorithmIdentifier)
		{
			int keySize = getKeySize(algorithmIdentifier.getAlgorithm());

			// just need the OID
			if (keySize > 0)
			{
				return keySize;
			}

			// TODO: support OID/Parameter key sizes (e.g. RC2).

			return -1;
		}

		public virtual int getKeySize(ASN1ObjectIdentifier algorithm)
		{
			int? keySize = (int?)KEY_SIZES.get(algorithm);

			if (keySize != null)
			{
				return keySize.Value;
			}

			return -1;
		}
	}

}