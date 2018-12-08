using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.bsi;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.eac;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.bc;
using org.bouncycastle.asn1.gm;

namespace org.bouncycastle.@operator
{

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

	public class DefaultDigestAlgorithmIdentifierFinder : DigestAlgorithmIdentifierFinder
	{
		private static Map digestOids = new HashMap();
		private static Map digestNameToOids = new HashMap();

		static DefaultDigestAlgorithmIdentifierFinder()
		{
			//
			// digests
			//
			digestOids.put(OIWObjectIdentifiers_Fields.md4WithRSAEncryption, PKCSObjectIdentifiers_Fields.md4);
			digestOids.put(OIWObjectIdentifiers_Fields.md4WithRSA, PKCSObjectIdentifiers_Fields.md4);
			digestOids.put(OIWObjectIdentifiers_Fields.sha1WithRSA, OIWObjectIdentifiers_Fields.idSHA1);

			digestOids.put(PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption, NISTObjectIdentifiers_Fields.id_sha224);
			digestOids.put(PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption, NISTObjectIdentifiers_Fields.id_sha256);
			digestOids.put(PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption, NISTObjectIdentifiers_Fields.id_sha384);
			digestOids.put(PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption, NISTObjectIdentifiers_Fields.id_sha512);
			digestOids.put(PKCSObjectIdentifiers_Fields.md2WithRSAEncryption, PKCSObjectIdentifiers_Fields.md2);
			digestOids.put(PKCSObjectIdentifiers_Fields.md4WithRSAEncryption, PKCSObjectIdentifiers_Fields.md4);
			digestOids.put(PKCSObjectIdentifiers_Fields.md5WithRSAEncryption, PKCSObjectIdentifiers_Fields.md5);
			digestOids.put(PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption, OIWObjectIdentifiers_Fields.idSHA1);

			digestOids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA1, OIWObjectIdentifiers_Fields.idSHA1);
			digestOids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA224, NISTObjectIdentifiers_Fields.id_sha224);
			digestOids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA256, NISTObjectIdentifiers_Fields.id_sha256);
			digestOids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA384, NISTObjectIdentifiers_Fields.id_sha384);
			digestOids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA512, NISTObjectIdentifiers_Fields.id_sha512);
			digestOids.put(X9ObjectIdentifiers_Fields.id_dsa_with_sha1, OIWObjectIdentifiers_Fields.idSHA1);

			digestOids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA1, OIWObjectIdentifiers_Fields.idSHA1);
			digestOids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA224, NISTObjectIdentifiers_Fields.id_sha224);
			digestOids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA256, NISTObjectIdentifiers_Fields.id_sha256);
			digestOids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA384, NISTObjectIdentifiers_Fields.id_sha384);
			digestOids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA512, NISTObjectIdentifiers_Fields.id_sha512);
			digestOids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_RIPEMD160, TeleTrusTObjectIdentifiers_Fields.ripemd160);

			digestOids.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_1, OIWObjectIdentifiers_Fields.idSHA1);
			digestOids.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_224, NISTObjectIdentifiers_Fields.id_sha224);
			digestOids.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_256, NISTObjectIdentifiers_Fields.id_sha256);
			digestOids.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_384, NISTObjectIdentifiers_Fields.id_sha384);
			digestOids.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_512, NISTObjectIdentifiers_Fields.id_sha512);

			digestOids.put(NISTObjectIdentifiers_Fields.dsa_with_sha224, NISTObjectIdentifiers_Fields.id_sha224);
			digestOids.put(NISTObjectIdentifiers_Fields.dsa_with_sha256, NISTObjectIdentifiers_Fields.id_sha256);
			digestOids.put(NISTObjectIdentifiers_Fields.dsa_with_sha384, NISTObjectIdentifiers_Fields.id_sha384);
			digestOids.put(NISTObjectIdentifiers_Fields.dsa_with_sha512, NISTObjectIdentifiers_Fields.id_sha512);

			digestOids.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_224, NISTObjectIdentifiers_Fields.id_sha3_224);
			digestOids.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_256, NISTObjectIdentifiers_Fields.id_sha3_256);
			digestOids.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_384, NISTObjectIdentifiers_Fields.id_sha3_384);
			digestOids.put(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_512, NISTObjectIdentifiers_Fields.id_sha3_512);
			digestOids.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_224, NISTObjectIdentifiers_Fields.id_sha3_224);
			digestOids.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_256, NISTObjectIdentifiers_Fields.id_sha3_256);
			digestOids.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_384, NISTObjectIdentifiers_Fields.id_sha3_384);
			digestOids.put(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_512, NISTObjectIdentifiers_Fields.id_sha3_512);
			digestOids.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_224, NISTObjectIdentifiers_Fields.id_sha3_224);
			digestOids.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_256, NISTObjectIdentifiers_Fields.id_sha3_256);
			digestOids.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_384, NISTObjectIdentifiers_Fields.id_sha3_384);
			digestOids.put(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_512, NISTObjectIdentifiers_Fields.id_sha3_512);

			digestOids.put(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128, TeleTrusTObjectIdentifiers_Fields.ripemd128);
			digestOids.put(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160, TeleTrusTObjectIdentifiers_Fields.ripemd160);
			digestOids.put(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256, TeleTrusTObjectIdentifiers_Fields.ripemd256);

			digestOids.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94, CryptoProObjectIdentifiers_Fields.gostR3411);
			digestOids.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001, CryptoProObjectIdentifiers_Fields.gostR3411);
			digestOids.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256, RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256);
			digestOids.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512, RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512);

			digestOids.put(BCObjectIdentifiers_Fields.sphincs256_with_SHA3_512, NISTObjectIdentifiers_Fields.id_sha3_512);
			digestOids.put(BCObjectIdentifiers_Fields.sphincs256_with_SHA512, NISTObjectIdentifiers_Fields.id_sha512);

			digestOids.put(GMObjectIdentifiers_Fields.sm2sign_with_sm3, GMObjectIdentifiers_Fields.sm3);

			digestNameToOids.put("SHA-1", OIWObjectIdentifiers_Fields.idSHA1);
			digestNameToOids.put("SHA-224", NISTObjectIdentifiers_Fields.id_sha224);
			digestNameToOids.put("SHA-256", NISTObjectIdentifiers_Fields.id_sha256);
			digestNameToOids.put("SHA-384", NISTObjectIdentifiers_Fields.id_sha384);
			digestNameToOids.put("SHA-512", NISTObjectIdentifiers_Fields.id_sha512);
			digestNameToOids.put("SHA-512-224", NISTObjectIdentifiers_Fields.id_sha512_224);
			digestNameToOids.put("SHA-512-256", NISTObjectIdentifiers_Fields.id_sha512_256);

			digestNameToOids.put("SHA1", OIWObjectIdentifiers_Fields.idSHA1);
			digestNameToOids.put("SHA224", NISTObjectIdentifiers_Fields.id_sha224);
			digestNameToOids.put("SHA256", NISTObjectIdentifiers_Fields.id_sha256);
			digestNameToOids.put("SHA384", NISTObjectIdentifiers_Fields.id_sha384);
			digestNameToOids.put("SHA512", NISTObjectIdentifiers_Fields.id_sha512);
			digestNameToOids.put("SHA512-224", NISTObjectIdentifiers_Fields.id_sha512_224);
			digestNameToOids.put("SHA512-256", NISTObjectIdentifiers_Fields.id_sha512_256);

			digestNameToOids.put("SHA3-224", NISTObjectIdentifiers_Fields.id_sha3_224);
			digestNameToOids.put("SHA3-256", NISTObjectIdentifiers_Fields.id_sha3_256);
			digestNameToOids.put("SHA3-384", NISTObjectIdentifiers_Fields.id_sha3_384);
			digestNameToOids.put("SHA3-512", NISTObjectIdentifiers_Fields.id_sha3_512);

			digestNameToOids.put("SHAKE-128", NISTObjectIdentifiers_Fields.id_shake128);
			digestNameToOids.put("SHAKE-256", NISTObjectIdentifiers_Fields.id_shake256);

			digestNameToOids.put("GOST3411", CryptoProObjectIdentifiers_Fields.gostR3411);
			digestNameToOids.put("GOST3411-2012-256", RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256);
			digestNameToOids.put("GOST3411-2012-512", RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512);

			digestNameToOids.put("MD2", PKCSObjectIdentifiers_Fields.md2);
			digestNameToOids.put("MD4", PKCSObjectIdentifiers_Fields.md4);
			digestNameToOids.put("MD5", PKCSObjectIdentifiers_Fields.md5);

			digestNameToOids.put("RIPEMD128", TeleTrusTObjectIdentifiers_Fields.ripemd128);
			digestNameToOids.put("RIPEMD160", TeleTrusTObjectIdentifiers_Fields.ripemd160);
			digestNameToOids.put("RIPEMD256", TeleTrusTObjectIdentifiers_Fields.ripemd256);

			digestNameToOids.put("SM3", GMObjectIdentifiers_Fields.sm3);
		}

		public virtual AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId)
		{
			AlgorithmIdentifier digAlgId;

			if (sigAlgId.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS))
			{
				digAlgId = RSASSAPSSparams.getInstance(sigAlgId.getParameters()).getHashAlgorithm();
			}
			else
			{
				digAlgId = new AlgorithmIdentifier((ASN1ObjectIdentifier)digestOids.get(sigAlgId.getAlgorithm()), DERNull.INSTANCE);
			}

			return digAlgId;
		}

		public virtual AlgorithmIdentifier find(string digAlgName)
		{
			return new AlgorithmIdentifier((ASN1ObjectIdentifier)digestNameToOids.get(digAlgName), DERNull.INSTANCE);
		}
	}
}