using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.eac;
using org.bouncycastle.asn1.bsi;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.gm;

namespace org.bouncycastle.cms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using BSIObjectIdentifiers = org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using GMObjectIdentifiers = org.bouncycastle.asn1.gm.GMObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

	public class DefaultCMSSignatureAlgorithmNameGenerator : CMSSignatureAlgorithmNameGenerator
	{
		private readonly Map encryptionAlgs = new HashMap();
		private readonly Map digestAlgs = new HashMap();

		private void addEntries(ASN1ObjectIdentifier alias, string digest, string encryption)
		{
			digestAlgs.put(alias, digest);
			encryptionAlgs.put(alias, encryption);
		}

		public DefaultCMSSignatureAlgorithmNameGenerator()
		{
			addEntries(NISTObjectIdentifiers_Fields.dsa_with_sha224, "SHA224", "DSA");
			addEntries(NISTObjectIdentifiers_Fields.dsa_with_sha256, "SHA256", "DSA");
			addEntries(NISTObjectIdentifiers_Fields.dsa_with_sha384, "SHA384", "DSA");
			addEntries(NISTObjectIdentifiers_Fields.dsa_with_sha512, "SHA512", "DSA");
			addEntries(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_224, "SHA3-224", "DSA");
			addEntries(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_256, "SHA3-256", "DSA");
			addEntries(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_384, "SHA3-384", "DSA");
			addEntries(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_512, "SHA3-512", "DSA");
			addEntries(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_224, "SHA3-224", "RSA");
			addEntries(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_256, "SHA3-256", "RSA");
			addEntries(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_384, "SHA3-384", "RSA");
			addEntries(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_512, "SHA3-512", "RSA");
			addEntries(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_224, "SHA3-224", "ECDSA");
			addEntries(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_256, "SHA3-256", "ECDSA");
			addEntries(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_384, "SHA3-384", "ECDSA");
			addEntries(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_512, "SHA3-512", "ECDSA");
			addEntries(OIWObjectIdentifiers_Fields.dsaWithSHA1, "SHA1", "DSA");
			addEntries(OIWObjectIdentifiers_Fields.md4WithRSA, "MD4", "RSA");
			addEntries(OIWObjectIdentifiers_Fields.md4WithRSAEncryption, "MD4", "RSA");
			addEntries(OIWObjectIdentifiers_Fields.md5WithRSA, "MD5", "RSA");
			addEntries(OIWObjectIdentifiers_Fields.sha1WithRSA, "SHA1", "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.md2WithRSAEncryption, "MD2", "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.md4WithRSAEncryption, "MD4", "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.md5WithRSAEncryption, "MD5", "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption, "SHA1", "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption, "SHA224", "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption, "SHA256", "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption, "SHA384", "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption, "SHA512", "RSA");

			addEntries(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128, "RIPEMD128", "RSA");
			addEntries(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160, "RIPEMD160", "RSA");
			addEntries(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256, "RIPEMD256", "RSA");

			addEntries(X9ObjectIdentifiers_Fields.ecdsa_with_SHA1, "SHA1", "ECDSA");
			addEntries(X9ObjectIdentifiers_Fields.ecdsa_with_SHA224, "SHA224", "ECDSA");
			addEntries(X9ObjectIdentifiers_Fields.ecdsa_with_SHA256, "SHA256", "ECDSA");
			addEntries(X9ObjectIdentifiers_Fields.ecdsa_with_SHA384, "SHA384", "ECDSA");
			addEntries(X9ObjectIdentifiers_Fields.ecdsa_with_SHA512, "SHA512", "ECDSA");
			addEntries(X9ObjectIdentifiers_Fields.id_dsa_with_sha1, "SHA1", "DSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_1, "SHA1", "ECDSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_224, "SHA224", "ECDSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_256, "SHA256", "ECDSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_384, "SHA384", "ECDSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_512, "SHA512", "ECDSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_RSA_v1_5_SHA_1, "SHA1", "RSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_RSA_v1_5_SHA_256, "SHA256", "RSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_RSA_PSS_SHA_1, "SHA1", "RSAandMGF1");
			addEntries(EACObjectIdentifiers_Fields.id_TA_RSA_PSS_SHA_256, "SHA256", "RSAandMGF1");
			addEntries(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA1, "SHA1", "PLAIN-ECDSA");
			addEntries(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA224, "SHA224", "PLAIN-ECDSA");
			addEntries(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA256, "SHA256", "PLAIN-ECDSA");
			addEntries(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA384, "SHA384", "PLAIN-ECDSA");
			addEntries(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA512, "SHA512", "PLAIN-ECDSA");
			addEntries(BSIObjectIdentifiers_Fields.ecdsa_plain_RIPEMD160, "RIPEMD160", "PLAIN-ECDSA");

			encryptionAlgs.put(X9ObjectIdentifiers_Fields.id_dsa, "DSA");
			encryptionAlgs.put(PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA");
			encryptionAlgs.put(TeleTrusTObjectIdentifiers_Fields.teleTrusTRSAsignatureAlgorithm, "RSA");
			encryptionAlgs.put(X509ObjectIdentifiers_Fields.id_ea_rsa, "RSA");
			encryptionAlgs.put(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS, "RSAandMGF1");
			encryptionAlgs.put(CryptoProObjectIdentifiers_Fields.gostR3410_94, "GOST3410");
			encryptionAlgs.put(CryptoProObjectIdentifiers_Fields.gostR3410_2001, "ECGOST3410");
			encryptionAlgs.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.6.2"), "ECGOST3410");
			encryptionAlgs.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.1.5"), "GOST3410");
			encryptionAlgs.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_256, "ECGOST3410-2012-256");
			encryptionAlgs.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512, "ECGOST3410-2012-512");
			encryptionAlgs.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001, "ECGOST3410");
			encryptionAlgs.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94, "GOST3410");
			encryptionAlgs.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256, "ECGOST3410-2012-256");
			encryptionAlgs.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512, "ECGOST3410-2012-512");
			encryptionAlgs.put(GMObjectIdentifiers_Fields.sm2sign_with_sm3, "SM2");

			digestAlgs.put(PKCSObjectIdentifiers_Fields.md2, "MD2");
			digestAlgs.put(PKCSObjectIdentifiers_Fields.md4, "MD4");
			digestAlgs.put(PKCSObjectIdentifiers_Fields.md5, "MD5");
			digestAlgs.put(OIWObjectIdentifiers_Fields.idSHA1, "SHA1");
			digestAlgs.put(NISTObjectIdentifiers_Fields.id_sha224, "SHA224");
			digestAlgs.put(NISTObjectIdentifiers_Fields.id_sha256, "SHA256");
			digestAlgs.put(NISTObjectIdentifiers_Fields.id_sha384, "SHA384");
			digestAlgs.put(NISTObjectIdentifiers_Fields.id_sha512, "SHA512");
			digestAlgs.put(NISTObjectIdentifiers_Fields.id_sha3_224, "SHA3-224");
			digestAlgs.put(NISTObjectIdentifiers_Fields.id_sha3_256, "SHA3-256");
			digestAlgs.put(NISTObjectIdentifiers_Fields.id_sha3_384, "SHA3-384");
			digestAlgs.put(NISTObjectIdentifiers_Fields.id_sha3_512, "SHA3-512");
			digestAlgs.put(TeleTrusTObjectIdentifiers_Fields.ripemd128, "RIPEMD128");
			digestAlgs.put(TeleTrusTObjectIdentifiers_Fields.ripemd160, "RIPEMD160");
			digestAlgs.put(TeleTrusTObjectIdentifiers_Fields.ripemd256, "RIPEMD256");
			digestAlgs.put(CryptoProObjectIdentifiers_Fields.gostR3411, "GOST3411");
			digestAlgs.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.2.1"), "GOST3411");
			digestAlgs.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256, "GOST3411-2012-256");
			digestAlgs.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512, "GOST3411-2012-512");
			digestAlgs.put(GMObjectIdentifiers_Fields.sm3, "SM3");
		}

		/// <summary>
		/// Return the digest algorithm using one of the standard JCA string
		/// representations rather than the algorithm identifier (if possible).
		/// </summary>
		private string getDigestAlgName(ASN1ObjectIdentifier digestAlgOID)
		{
			string algName = (string)digestAlgs.get(digestAlgOID);

			if (!string.ReferenceEquals(algName, null))
			{
				return algName;
			}

			return digestAlgOID.getId();
		}

		/// <summary>
		/// Return the digest encryption algorithm using one of the standard
		/// JCA string representations rather the the algorithm identifier (if
		/// possible).
		/// </summary>
		private string getEncryptionAlgName(ASN1ObjectIdentifier encryptionAlgOID)
		{
			string algName = (string)encryptionAlgs.get(encryptionAlgOID);

			if (!string.ReferenceEquals(algName, null))
			{
				return algName;
			}

			return encryptionAlgOID.getId();
		}

		/// <summary>
		/// Set the mapping for the encryption algorithm used in association with a SignedData generation
		/// or interpretation.
		/// </summary>
		/// <param name="oid"> object identifier to map. </param>
		/// <param name="algorithmName"> algorithm name to use. </param>
		public virtual void setSigningEncryptionAlgorithmMapping(ASN1ObjectIdentifier oid, string algorithmName)
		{
			encryptionAlgs.put(oid, algorithmName);
		}

		/// <summary>
		/// Set the mapping for the digest algorithm to use in conjunction with a SignedData generation
		/// or interpretation.
		/// </summary>
		/// <param name="oid"> object identifier to map. </param>
		/// <param name="algorithmName"> algorithm name to use. </param>
		public virtual void setSigningDigestAlgorithmMapping(ASN1ObjectIdentifier oid, string algorithmName)
		{
			digestAlgs.put(oid, algorithmName);
		}

		public virtual string getSignatureName(AlgorithmIdentifier digestAlg, AlgorithmIdentifier encryptionAlg)
		{
			string digestName = getDigestAlgName(encryptionAlg.getAlgorithm());

			if (!digestName.Equals(encryptionAlg.getAlgorithm().getId()))
			{
				return digestName + "with" + getEncryptionAlgName(encryptionAlg.getAlgorithm());
			}

			return getDigestAlgName(digestAlg.getAlgorithm()) + "with" + getEncryptionAlgName(encryptionAlg.getAlgorithm());
		}
	}

}