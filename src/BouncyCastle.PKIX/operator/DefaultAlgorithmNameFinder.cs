using org.bouncycastle.asn1.bsi;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.eac;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.gnu;
using org.bouncycastle.asn1.ntt;
using org.bouncycastle.asn1.kisa;
using org.bouncycastle.asn1.misc;

namespace org.bouncycastle.@operator
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using BSIObjectIdentifiers = org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using GNUObjectIdentifiers = org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
	using KISAObjectIdentifiers = org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

	public class DefaultAlgorithmNameFinder : AlgorithmNameFinder
	{
		private static readonly Map algorithms = new HashMap();

		static DefaultAlgorithmNameFinder()
		{
			algorithms.put(BSIObjectIdentifiers_Fields.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
			algorithms.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
			algorithms.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
			algorithms.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
			algorithms.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
			algorithms.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
			algorithms.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
			algorithms.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410-2001");
			algorithms.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001, "GOST3411WITHGOST3410-2001");
			algorithms.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
			algorithms.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410-94");
			algorithms.put(CryptoProObjectIdentifiers_Fields.gostR3411, "GOST3411");
			algorithms.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411WITHGOST3410-2012-256");
			algorithms.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411WITHGOST3410-2012-512");
			algorithms.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411WITHECGOST3410-2012-256");
			algorithms.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411WITHECGOST3410-2012-512");
			algorithms.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256WITHGOST3410-2012-256");
			algorithms.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512WITHGOST3410-2012-512");
			algorithms.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256WITHECGOST3410-2012-256");
			algorithms.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512WITHECGOST3410-2012-512");
			algorithms.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
			algorithms.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
			algorithms.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
			algorithms.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
			algorithms.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");

			algorithms.put(NISTObjectIdentifiers_Fields.id_sha224, "SHA224");
			algorithms.put(NISTObjectIdentifiers_Fields.id_sha256, "SHA256");
			algorithms.put(NISTObjectIdentifiers_Fields.id_sha384, "SHA384");
			algorithms.put(NISTObjectIdentifiers_Fields.id_sha512, "SHA512");
			algorithms.put(NISTObjectIdentifiers_Fields.id_sha3_224, "SHA3-224");
			algorithms.put(NISTObjectIdentifiers_Fields.id_sha3_256, "SHA3-256");
			algorithms.put(NISTObjectIdentifiers_Fields.id_sha3_384, "SHA3-384");
			algorithms.put(NISTObjectIdentifiers_Fields.id_sha3_512, "SHA3-512");
			algorithms.put(OIWObjectIdentifiers_Fields.elGamalAlgorithm, "ELGAMAL");
			algorithms.put(OIWObjectIdentifiers_Fields.idSHA1, "SHA1");
			algorithms.put(OIWObjectIdentifiers_Fields.md5WithRSA, "MD5WITHRSA");
			algorithms.put(OIWObjectIdentifiers_Fields.sha1WithRSA, "SHA1WITHRSA");
			algorithms.put(PKCSObjectIdentifiers_Fields.id_RSAES_OAEP, "RSAOAEP");
			algorithms.put(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS, "RSAPSS");
			algorithms.put(PKCSObjectIdentifiers_Fields.md2WithRSAEncryption, "MD2WITHRSA");
			algorithms.put(PKCSObjectIdentifiers_Fields.md5, "MD5");
			algorithms.put(PKCSObjectIdentifiers_Fields.md5WithRSAEncryption, "MD5WITHRSA");
			algorithms.put(PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA");
			algorithms.put(PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption, "SHA1WITHRSA");
			algorithms.put(PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption, "SHA224WITHRSA");
			algorithms.put(PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption, "SHA256WITHRSA");
			algorithms.put(PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption, "SHA384WITHRSA");
			algorithms.put(PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption, "SHA512WITHRSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_224, "SHA3-224WITHRSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_256, "SHA3-256WITHRSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_384, "SHA3-384WITHRSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_512, "SHA3-512WITHRSA");
			algorithms.put(TeleTrusTObjectIdentifiers_Fields.ripemd128, "RIPEMD128");
			algorithms.put(TeleTrusTObjectIdentifiers_Fields.ripemd160, "RIPEMD160");
			algorithms.put(TeleTrusTObjectIdentifiers_Fields.ripemd256, "RIPEMD256");
			algorithms.put(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128, "RIPEMD128WITHRSA");
			algorithms.put(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160, "RIPEMD160WITHRSA");
			algorithms.put(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256, "RIPEMD256WITHRSA");
			algorithms.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA1, "ECDSAWITHSHA1");
			algorithms.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA1, "SHA1WITHECDSA");
			algorithms.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA224, "SHA224WITHECDSA");
			algorithms.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA256, "SHA256WITHECDSA");
			algorithms.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA384, "SHA384WITHECDSA");
			algorithms.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA512, "SHA512WITHECDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_224, "SHA3-224WITHECDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_256, "SHA3-256WITHECDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_384, "SHA3-384WITHECDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_512, "SHA3-512WITHECDSA");
			algorithms.put(X9ObjectIdentifiers_Fields.id_dsa_with_sha1, "SHA1WITHDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.dsa_with_sha224, "SHA224WITHDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.dsa_with_sha256, "SHA256WITHDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.dsa_with_sha384, "SHA384WITHDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.dsa_with_sha512, "SHA512WITHDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_224, "SHA3-224WITHDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_256, "SHA3-256WITHDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_384, "SHA3-384WITHDSA");
			algorithms.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_512, "SHA3-512WITHDSA");
			algorithms.put(GNUObjectIdentifiers_Fields.Tiger_192, "Tiger");

			algorithms.put(PKCSObjectIdentifiers_Fields.RC2_CBC, "RC2/CBC");
			algorithms.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC, "DESEDE-3KEY/CBC");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes128_ECB, "AES-128/ECB");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes192_ECB, "AES-192/ECB");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes256_ECB, "AES-256/ECB");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes128_CBC, "AES-128/CBC");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes192_CBC, "AES-192/CBC");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes256_CBC, "AES-256/CBC");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes128_CFB, "AES-128/CFB");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes192_CFB, "AES-192/CFB");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes256_CFB, "AES-256/CFB");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes128_OFB, "AES-128/OFB");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes192_OFB, "AES-192/OFB");
			algorithms.put(NISTObjectIdentifiers_Fields.id_aes256_OFB, "AES-256/OFB");
			algorithms.put(NTTObjectIdentifiers_Fields.id_camellia128_cbc, "CAMELLIA-128/CBC");
			algorithms.put(NTTObjectIdentifiers_Fields.id_camellia192_cbc, "CAMELLIA-192/CBC");
			algorithms.put(NTTObjectIdentifiers_Fields.id_camellia256_cbc, "CAMELLIA-256/CBC");
			algorithms.put(KISAObjectIdentifiers_Fields.id_seedCBC, "SEED/CBC");
			algorithms.put(MiscObjectIdentifiers_Fields.as_sys_sec_alg_ideaCBC, "IDEA/CBC");
			algorithms.put(MiscObjectIdentifiers_Fields.cast5CBC, "CAST5/CBC");
			algorithms.put(MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_ECB, "Blowfish/ECB");
			algorithms.put(MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_CBC, "Blowfish/CBC");
			algorithms.put(MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_CFB, "Blowfish/CFB");
			algorithms.put(MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_OFB, "Blowfish/OFB");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_128_ECB, "Serpent-128/ECB");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_128_CBC, "Serpent-128/CBC");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_128_CFB, "Serpent-128/CFB");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_128_OFB, "Serpent-128/OFB");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_192_ECB, "Serpent-192/ECB");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_192_CBC, "Serpent-192/CBC");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_192_CFB, "Serpent-192/CFB");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_192_OFB, "Serpent-192/OFB");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_256_ECB, "Serpent-256/ECB");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_256_CBC, "Serpent-256/CBC");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_256_CFB, "Serpent-256/CFB");
			algorithms.put(GNUObjectIdentifiers_Fields.Serpent_256_OFB, "Serpent-256/OFB");
		}

		public virtual bool hasAlgorithmName(ASN1ObjectIdentifier objectIdentifier)
		{
			return algorithms.containsKey(objectIdentifier);
		}

		public virtual string getAlgorithmName(ASN1ObjectIdentifier objectIdentifier)
		{
			string name = (string)algorithms.get(objectIdentifier);

			return (!string.ReferenceEquals(name, null)) ? name : objectIdentifier.getId();
		}

		public virtual string getAlgorithmName(AlgorithmIdentifier algorithmIdentifier)
		{
			// TODO: take into account PSS/OAEP params
			return getAlgorithmName(algorithmIdentifier.getAlgorithm());
		}
	}

}