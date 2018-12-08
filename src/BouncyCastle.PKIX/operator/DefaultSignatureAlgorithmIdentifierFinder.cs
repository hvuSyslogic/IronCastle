using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.bsi;
using org.bouncycastle.asn1.eac;
using org.bouncycastle.asn1.bc;
using org.bouncycastle.asn1.gm;
using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.@operator
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using BCObjectIdentifiers = org.bouncycastle.asn1.bc.BCObjectIdentifiers;
	using BSIObjectIdentifiers = org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using GMObjectIdentifiers = org.bouncycastle.asn1.gm.GMObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSASSAPSSparams = org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using Strings = org.bouncycastle.util.Strings;

	public class DefaultSignatureAlgorithmIdentifierFinder : SignatureAlgorithmIdentifierFinder
	{
		private static Map algorithms = new HashMap();
		private static Set noParams = new HashSet();
		private static Map @params = new HashMap();
		private static Set pkcs15RsaEncryption = new HashSet();
		private static Map digestOids = new HashMap();

		private static readonly ASN1ObjectIdentifier ENCRYPTION_RSA = PKCSObjectIdentifiers_Fields.rsaEncryption;
		private static readonly ASN1ObjectIdentifier ENCRYPTION_DSA = X9ObjectIdentifiers_Fields.id_dsa_with_sha1;
		private static readonly ASN1ObjectIdentifier ENCRYPTION_ECDSA = X9ObjectIdentifiers_Fields.ecdsa_with_SHA1;
		private static readonly ASN1ObjectIdentifier ENCRYPTION_RSA_PSS = PKCSObjectIdentifiers_Fields.id_RSASSA_PSS;
		private static readonly ASN1ObjectIdentifier ENCRYPTION_GOST3410 = CryptoProObjectIdentifiers_Fields.gostR3410_94;
		private static readonly ASN1ObjectIdentifier ENCRYPTION_ECGOST3410 = CryptoProObjectIdentifiers_Fields.gostR3410_2001;
		private static readonly ASN1ObjectIdentifier ENCRYPTION_ECGOST3410_2012_256 = RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_256;
		private static readonly ASN1ObjectIdentifier ENCRYPTION_ECGOST3410_2012_512 = RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512;

		static DefaultSignatureAlgorithmIdentifierFinder()
		{
			algorithms.put("MD2WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.md2WithRSAEncryption);
			algorithms.put("MD2WITHRSA", PKCSObjectIdentifiers_Fields.md2WithRSAEncryption);
			algorithms.put("MD5WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.md5WithRSAEncryption);
			algorithms.put("MD5WITHRSA", PKCSObjectIdentifiers_Fields.md5WithRSAEncryption);
			algorithms.put("SHA1WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption);
			algorithms.put("SHA1WITHRSA", PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption);
			algorithms.put("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption);
			algorithms.put("SHA224WITHRSA", PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption);
			algorithms.put("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption);
			algorithms.put("SHA256WITHRSA", PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption);
			algorithms.put("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption);
			algorithms.put("SHA384WITHRSA", PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption);
			algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption);
			algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption);
			algorithms.put("SHA1WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA224WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA256WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA384WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA512WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA3-224WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA3-256WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA3-384WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA3-512WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160);
			algorithms.put("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160);
			algorithms.put("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128);
			algorithms.put("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128);
			algorithms.put("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256);
			algorithms.put("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256);
			algorithms.put("SHA1WITHDSA", X9ObjectIdentifiers_Fields.id_dsa_with_sha1);
			algorithms.put("DSAWITHSHA1", X9ObjectIdentifiers_Fields.id_dsa_with_sha1);
			algorithms.put("SHA224WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha224);
			algorithms.put("SHA256WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha256);
			algorithms.put("SHA384WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha384);
			algorithms.put("SHA512WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha512);
			algorithms.put("SHA3-224WITHDSA", NISTObjectIdentifiers_Fields.id_dsa_with_sha3_224);
			algorithms.put("SHA3-256WITHDSA", NISTObjectIdentifiers_Fields.id_dsa_with_sha3_256);
			algorithms.put("SHA3-384WITHDSA", NISTObjectIdentifiers_Fields.id_dsa_with_sha3_384);
			algorithms.put("SHA3-512WITHDSA", NISTObjectIdentifiers_Fields.id_dsa_with_sha3_512);
			algorithms.put("SHA3-224WITHECDSA", NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_224);
			algorithms.put("SHA3-256WITHECDSA", NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_256);
			algorithms.put("SHA3-384WITHECDSA", NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_384);
			algorithms.put("SHA3-512WITHECDSA", NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_512);
			algorithms.put("SHA3-224WITHRSA", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_224);
			algorithms.put("SHA3-256WITHRSA", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_256);
			algorithms.put("SHA3-384WITHRSA", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_384);
			algorithms.put("SHA3-512WITHRSA", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_512);
			algorithms.put("SHA3-224WITHRSAENCRYPTION", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_224);
			algorithms.put("SHA3-256WITHRSAENCRYPTION", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_256);
			algorithms.put("SHA3-384WITHRSAENCRYPTION", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_384);
			algorithms.put("SHA3-512WITHRSAENCRYPTION", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_512);
			algorithms.put("SHA1WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA1);
			algorithms.put("ECDSAWITHSHA1", X9ObjectIdentifiers_Fields.ecdsa_with_SHA1);
			algorithms.put("SHA224WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA224);
			algorithms.put("SHA256WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA256);
			algorithms.put("SHA384WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA384);
			algorithms.put("SHA512WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA512);
			algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94);
			algorithms.put("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94);
			algorithms.put("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);
			algorithms.put("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);
			algorithms.put("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);
			algorithms.put("GOST3411WITHECGOST3410-2012-256", RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256);
			algorithms.put("GOST3411WITHECGOST3410-2012-512", RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512);
			algorithms.put("GOST3411WITHGOST3410-2012-256", RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256);
			algorithms.put("GOST3411WITHGOST3410-2012-512", RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512);
			algorithms.put("GOST3411-2012-256WITHECGOST3410-2012-256", RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256);
			algorithms.put("GOST3411-2012-512WITHECGOST3410-2012-512", RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512);
			algorithms.put("GOST3411-2012-256WITHGOST3410-2012-256", RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256);
			algorithms.put("GOST3411-2012-512WITHGOST3410-2012-512", RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512);
			algorithms.put("SHA1WITHPLAIN-ECDSA", BSIObjectIdentifiers_Fields.ecdsa_plain_SHA1);
			algorithms.put("SHA224WITHPLAIN-ECDSA", BSIObjectIdentifiers_Fields.ecdsa_plain_SHA224);
			algorithms.put("SHA256WITHPLAIN-ECDSA", BSIObjectIdentifiers_Fields.ecdsa_plain_SHA256);
			algorithms.put("SHA384WITHPLAIN-ECDSA", BSIObjectIdentifiers_Fields.ecdsa_plain_SHA384);
			algorithms.put("SHA512WITHPLAIN-ECDSA", BSIObjectIdentifiers_Fields.ecdsa_plain_SHA512);
			algorithms.put("RIPEMD160WITHPLAIN-ECDSA", BSIObjectIdentifiers_Fields.ecdsa_plain_RIPEMD160);
			algorithms.put("SHA1WITHCVC-ECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_1);
			algorithms.put("SHA224WITHCVC-ECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_224);
			algorithms.put("SHA256WITHCVC-ECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_256);
			algorithms.put("SHA384WITHCVC-ECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_384);
			algorithms.put("SHA512WITHCVC-ECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_512);
			algorithms.put("SHA3-512WITHSPHINCS256", BCObjectIdentifiers_Fields.sphincs256_with_SHA3_512);
			algorithms.put("SHA512WITHSPHINCS256", BCObjectIdentifiers_Fields.sphincs256_with_SHA512);
			algorithms.put("SM3WITHSM2", GMObjectIdentifiers_Fields.sm2sign_with_sm3);

			algorithms.put("SHA256WITHXMSS", BCObjectIdentifiers_Fields.xmss_SHA256ph);
			algorithms.put("SHA512WITHXMSS", BCObjectIdentifiers_Fields.xmss_SHA512ph);
			algorithms.put("SHAKE128WITHXMSS", BCObjectIdentifiers_Fields.xmss_SHAKE128ph);
			algorithms.put("SHAKE256WITHXMSS", BCObjectIdentifiers_Fields.xmss_SHAKE256ph);

			algorithms.put("SHA256WITHXMSSMT", BCObjectIdentifiers_Fields.xmss_mt_SHA256ph);
			algorithms.put("SHA512WITHXMSSMT", BCObjectIdentifiers_Fields.xmss_mt_SHA512ph);
			algorithms.put("SHAKE128WITHXMSSMT", BCObjectIdentifiers_Fields.xmss_mt_SHAKE128ph);
			algorithms.put("SHAKE256WITHXMSSMT", BCObjectIdentifiers_Fields.xmss_mt_SHAKE256ph);

			algorithms.put("SHA256WITHXMSS-SHA256", BCObjectIdentifiers_Fields.xmss_SHA256ph);
			algorithms.put("SHA512WITHXMSS-SHA512", BCObjectIdentifiers_Fields.xmss_SHA512ph);
			algorithms.put("SHAKE128WITHXMSS-SHAKE128", BCObjectIdentifiers_Fields.xmss_SHAKE128ph);
			algorithms.put("SHAKE256WITHXMSS-SHAKE256", BCObjectIdentifiers_Fields.xmss_SHAKE256ph);

			algorithms.put("SHA256WITHXMSSMT-SHA256", BCObjectIdentifiers_Fields.xmss_mt_SHA256ph);
			algorithms.put("SHA512WITHXMSSMT-SHA512", BCObjectIdentifiers_Fields.xmss_mt_SHA512ph);
			algorithms.put("SHAKE128WITHXMSSMT-SHAKE128", BCObjectIdentifiers_Fields.xmss_mt_SHAKE128ph);
			algorithms.put("SHAKE256WITHXMSSMT-SHAKE256", BCObjectIdentifiers_Fields.xmss_mt_SHAKE256ph);

			algorithms.put("XMSS-SHA256", BCObjectIdentifiers_Fields.xmss_SHA256);
			algorithms.put("XMSS-SHA512", BCObjectIdentifiers_Fields.xmss_SHA512);
			algorithms.put("XMSS-SHAKE128", BCObjectIdentifiers_Fields.xmss_SHAKE128);
			algorithms.put("XMSS-SHAKE256", BCObjectIdentifiers_Fields.xmss_SHAKE256);

			algorithms.put("XMSSMT-SHA256", BCObjectIdentifiers_Fields.xmss_mt_SHA256);
			algorithms.put("XMSSMT-SHA512", BCObjectIdentifiers_Fields.xmss_mt_SHA512);
			algorithms.put("XMSSMT-SHAKE128", BCObjectIdentifiers_Fields.xmss_mt_SHAKE128);
			algorithms.put("XMSSMT-SHAKE256", BCObjectIdentifiers_Fields.xmss_mt_SHAKE256);

			algorithms.put("QTESLA-I", BCObjectIdentifiers_Fields.qTESLA_I);
			algorithms.put("QTESLA-III-SIZE", BCObjectIdentifiers_Fields.qTESLA_III_size);
			algorithms.put("QTESLA-III-SPEED", BCObjectIdentifiers_Fields.qTESLA_III_speed);
			algorithms.put("QTESLA-P-I", BCObjectIdentifiers_Fields.qTESLA_p_I);
			algorithms.put("QTESLA-P-III", BCObjectIdentifiers_Fields.qTESLA_p_III);

			//
			// According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
			// The parameters field SHALL be NULL for RSA based signature algorithms.
			//
			noParams.add(X9ObjectIdentifiers_Fields.ecdsa_with_SHA1);
			noParams.add(X9ObjectIdentifiers_Fields.ecdsa_with_SHA224);
			noParams.add(X9ObjectIdentifiers_Fields.ecdsa_with_SHA256);
			noParams.add(X9ObjectIdentifiers_Fields.ecdsa_with_SHA384);
			noParams.add(X9ObjectIdentifiers_Fields.ecdsa_with_SHA512);
			noParams.add(X9ObjectIdentifiers_Fields.id_dsa_with_sha1);
			noParams.add(NISTObjectIdentifiers_Fields.dsa_with_sha224);
			noParams.add(NISTObjectIdentifiers_Fields.dsa_with_sha256);
			noParams.add(NISTObjectIdentifiers_Fields.dsa_with_sha384);
			noParams.add(NISTObjectIdentifiers_Fields.dsa_with_sha512);
			noParams.add(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_224);
			noParams.add(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_256);
			noParams.add(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_384);
			noParams.add(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_512);
			noParams.add(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_224);
			noParams.add(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_256);
			noParams.add(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_384);
			noParams.add(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_512);

			//
			// RFC 4491
			//
			noParams.add(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94);
			noParams.add(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);
			noParams.add(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256);
			noParams.add(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512);

			//
			// SPHINCS-256
			//
			noParams.add(BCObjectIdentifiers_Fields.sphincs256_with_SHA512);
			noParams.add(BCObjectIdentifiers_Fields.sphincs256_with_SHA3_512);

			//
			// XMSS
			//
			noParams.add(BCObjectIdentifiers_Fields.xmss_SHA256ph);
			noParams.add(BCObjectIdentifiers_Fields.xmss_SHA512ph);
			noParams.add(BCObjectIdentifiers_Fields.xmss_SHAKE128ph);
			noParams.add(BCObjectIdentifiers_Fields.xmss_SHAKE256ph);
			noParams.add(BCObjectIdentifiers_Fields.xmss_mt_SHA256ph);
			noParams.add(BCObjectIdentifiers_Fields.xmss_mt_SHA512ph);
			noParams.add(BCObjectIdentifiers_Fields.xmss_mt_SHAKE128ph);
			noParams.add(BCObjectIdentifiers_Fields.xmss_mt_SHAKE256ph);

			noParams.add(BCObjectIdentifiers_Fields.xmss_SHA256);
			noParams.add(BCObjectIdentifiers_Fields.xmss_SHA512);
			noParams.add(BCObjectIdentifiers_Fields.xmss_SHAKE128);
			noParams.add(BCObjectIdentifiers_Fields.xmss_SHAKE256);
			noParams.add(BCObjectIdentifiers_Fields.xmss_mt_SHA256);
			noParams.add(BCObjectIdentifiers_Fields.xmss_mt_SHA512);
			noParams.add(BCObjectIdentifiers_Fields.xmss_mt_SHAKE128);
			noParams.add(BCObjectIdentifiers_Fields.xmss_mt_SHAKE256);

			//
			// qTESLA
			//
			noParams.add(BCObjectIdentifiers_Fields.qTESLA_I);
			noParams.add(BCObjectIdentifiers_Fields.qTESLA_III_size);
			noParams.add(BCObjectIdentifiers_Fields.qTESLA_III_speed);
			noParams.add(BCObjectIdentifiers_Fields.qTESLA_p_I);
			noParams.add(BCObjectIdentifiers_Fields.qTESLA_p_III);

			//
			// SM2
			//
			noParams.add(GMObjectIdentifiers_Fields.sm2sign_with_sm3);

			//
			// PKCS 1.5 encrypted  algorithms
			//
			pkcs15RsaEncryption.add(PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption);
			pkcs15RsaEncryption.add(PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption);
			pkcs15RsaEncryption.add(PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption);
			pkcs15RsaEncryption.add(PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption);
			pkcs15RsaEncryption.add(PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption);
			pkcs15RsaEncryption.add(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128);
			pkcs15RsaEncryption.add(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160);
			pkcs15RsaEncryption.add(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256);
			pkcs15RsaEncryption.add(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_224);
			pkcs15RsaEncryption.add(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_256);
			pkcs15RsaEncryption.add(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_384);
			pkcs15RsaEncryption.add(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_512);

			//
			// explicit params
			//
			AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE);
			@params.put("SHA1WITHRSAANDMGF1", createPSSParams(sha1AlgId, 20));

			AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha224, DERNull.INSTANCE);
			@params.put("SHA224WITHRSAANDMGF1", createPSSParams(sha224AlgId, 28));

			AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha256, DERNull.INSTANCE);
			@params.put("SHA256WITHRSAANDMGF1", createPSSParams(sha256AlgId, 32));

			AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha384, DERNull.INSTANCE);
			@params.put("SHA384WITHRSAANDMGF1", createPSSParams(sha384AlgId, 48));

			AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512, DERNull.INSTANCE);
			@params.put("SHA512WITHRSAANDMGF1", createPSSParams(sha512AlgId, 64));

			AlgorithmIdentifier sha3_224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha3_224, DERNull.INSTANCE);
			@params.put("SHA3-224WITHRSAANDMGF1", createPSSParams(sha3_224AlgId, 28));

			AlgorithmIdentifier sha3_256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha3_256, DERNull.INSTANCE);
			@params.put("SHA3-256WITHRSAANDMGF1", createPSSParams(sha3_256AlgId, 32));

			AlgorithmIdentifier sha3_384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha3_384, DERNull.INSTANCE);
			@params.put("SHA3-384WITHRSAANDMGF1", createPSSParams(sha3_384AlgId, 48));

			AlgorithmIdentifier sha3_512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha3_512, DERNull.INSTANCE);
			@params.put("SHA3-512WITHRSAANDMGF1", createPSSParams(sha3_512AlgId, 64));

			//
			// digests
			//
			digestOids.put(PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption, NISTObjectIdentifiers_Fields.id_sha224);
			digestOids.put(PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption, NISTObjectIdentifiers_Fields.id_sha256);
			digestOids.put(PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption, NISTObjectIdentifiers_Fields.id_sha384);
			digestOids.put(PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption, NISTObjectIdentifiers_Fields.id_sha512);
			digestOids.put(NISTObjectIdentifiers_Fields.dsa_with_sha224, NISTObjectIdentifiers_Fields.id_sha224);
			digestOids.put(NISTObjectIdentifiers_Fields.dsa_with_sha256, NISTObjectIdentifiers_Fields.id_sha256);
			digestOids.put(NISTObjectIdentifiers_Fields.dsa_with_sha384, NISTObjectIdentifiers_Fields.id_sha384);
			digestOids.put(NISTObjectIdentifiers_Fields.dsa_with_sha512, NISTObjectIdentifiers_Fields.id_sha512);
			digestOids.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_224, NISTObjectIdentifiers_Fields.id_sha3_224);
			digestOids.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_256, NISTObjectIdentifiers_Fields.id_sha3_256);
			digestOids.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_384, NISTObjectIdentifiers_Fields.id_sha3_384);
			digestOids.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_512, NISTObjectIdentifiers_Fields.id_sha3_512);
			digestOids.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_224, NISTObjectIdentifiers_Fields.id_sha3_224);
			digestOids.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_256, NISTObjectIdentifiers_Fields.id_sha3_256);
			digestOids.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_384, NISTObjectIdentifiers_Fields.id_sha3_384);
			digestOids.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_512, NISTObjectIdentifiers_Fields.id_sha3_512);
			digestOids.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_224, NISTObjectIdentifiers_Fields.id_sha3_224);
			digestOids.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_256, NISTObjectIdentifiers_Fields.id_sha3_256);
			digestOids.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_384, NISTObjectIdentifiers_Fields.id_sha3_384);
			digestOids.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_512, NISTObjectIdentifiers_Fields.id_sha3_512);

			digestOids.put(PKCSObjectIdentifiers_Fields.md2WithRSAEncryption, PKCSObjectIdentifiers_Fields.md2);
			digestOids.put(PKCSObjectIdentifiers_Fields.md4WithRSAEncryption, PKCSObjectIdentifiers_Fields.md4);
			digestOids.put(PKCSObjectIdentifiers_Fields.md5WithRSAEncryption, PKCSObjectIdentifiers_Fields.md5);
			digestOids.put(PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption, OIWObjectIdentifiers_Fields.idSHA1);
			digestOids.put(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128, TeleTrusTObjectIdentifiers_Fields.ripemd128);
			digestOids.put(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160, TeleTrusTObjectIdentifiers_Fields.ripemd160);
			digestOids.put(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256, TeleTrusTObjectIdentifiers_Fields.ripemd256);
			digestOids.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94, CryptoProObjectIdentifiers_Fields.gostR3411);
			digestOids.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001, CryptoProObjectIdentifiers_Fields.gostR3411);
			digestOids.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256, RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256);
			digestOids.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512, RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512);
			digestOids.put(GMObjectIdentifiers_Fields.sm2sign_with_sm3, GMObjectIdentifiers_Fields.sm3);
		}

		private static AlgorithmIdentifier generate(string signatureAlgorithm)
		{
			AlgorithmIdentifier sigAlgId;

			string algorithmName = Strings.toUpperCase(signatureAlgorithm);
			ASN1ObjectIdentifier sigOID = (ASN1ObjectIdentifier)algorithms.get(algorithmName);
			if (sigOID == null)
			{
				throw new IllegalArgumentException("Unknown signature type requested: " + algorithmName);
			}

			if (noParams.contains(sigOID))
			{
				sigAlgId = new AlgorithmIdentifier(sigOID);
			}
			else if (@params.containsKey(algorithmName))
			{
				sigAlgId = new AlgorithmIdentifier(sigOID, (ASN1Encodable)@params.get(algorithmName));
			}
			else
			{
				sigAlgId = new AlgorithmIdentifier(sigOID, DERNull.INSTANCE);
			}

			return sigAlgId;
		}

		private static RSASSAPSSparams createPSSParams(AlgorithmIdentifier hashAlgId, int saltSize)
		{
			return new RSASSAPSSparams(hashAlgId, new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_mgf1, hashAlgId), new ASN1Integer(saltSize), new ASN1Integer(1));
		}

		public virtual AlgorithmIdentifier find(string sigAlgName)
		{
			return generate(sigAlgName);
		}
	}
}