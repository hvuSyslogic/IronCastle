using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.eac;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using OtherRevocationInfoFormat = org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AttributeCertificate = org.bouncycastle.asn1.x509.AttributeCertificate;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using X509AttributeCertificateHolder = org.bouncycastle.cert.X509AttributeCertificateHolder;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using CollectionStore = org.bouncycastle.util.CollectionStore;
	using Store = org.bouncycastle.util.Store;

	public class CMSSignedHelper
	{
		internal static readonly CMSSignedHelper INSTANCE = new CMSSignedHelper();

		private static readonly Map encryptionAlgs = new HashMap();

		private static void addEntries(ASN1ObjectIdentifier alias, string encryption)
		{
			encryptionAlgs.put(alias.getId(), encryption);
		}

		static CMSSignedHelper()
		{
			addEntries(NISTObjectIdentifiers_Fields.dsa_with_sha224, "DSA");
			addEntries(NISTObjectIdentifiers_Fields.dsa_with_sha256, "DSA");
			addEntries(NISTObjectIdentifiers_Fields.dsa_with_sha384, "DSA");
			addEntries(NISTObjectIdentifiers_Fields.dsa_with_sha512, "DSA");
			addEntries(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_224, "DSA");
			addEntries(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_256, "DSA");
			addEntries(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_384, "DSA");
			addEntries(NISTObjectIdentifiers_Fields.id_dsa_with_sha3_512, "DSA");
			addEntries(OIWObjectIdentifiers_Fields.dsaWithSHA1, "DSA");
			addEntries(OIWObjectIdentifiers_Fields.md4WithRSA, "RSA");
			addEntries(OIWObjectIdentifiers_Fields.md4WithRSAEncryption, "RSA");
			addEntries(OIWObjectIdentifiers_Fields.md5WithRSA, "RSA");
			addEntries(OIWObjectIdentifiers_Fields.sha1WithRSA, "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.md2WithRSAEncryption, "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.md4WithRSAEncryption, "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.md5WithRSAEncryption, "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption, "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption, "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption, "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption, "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption, "RSA");
			addEntries(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_224, "RSA");
			addEntries(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_256, "RSA");
			addEntries(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_384, "RSA");
			addEntries(NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_512, "RSA");
			addEntries(X9ObjectIdentifiers_Fields.ecdsa_with_SHA1, "ECDSA");
			addEntries(X9ObjectIdentifiers_Fields.ecdsa_with_SHA224, "ECDSA");
			addEntries(X9ObjectIdentifiers_Fields.ecdsa_with_SHA256, "ECDSA");
			addEntries(X9ObjectIdentifiers_Fields.ecdsa_with_SHA384, "ECDSA");
			addEntries(X9ObjectIdentifiers_Fields.ecdsa_with_SHA512, "ECDSA");
			addEntries(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_224, "ECDSA");
			addEntries(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_256, "ECDSA");
			addEntries(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_384, "ECDSA");
			addEntries(NISTObjectIdentifiers_Fields.id_ecdsa_with_sha3_512, "ECDSA");
			addEntries(X9ObjectIdentifiers_Fields.id_dsa_with_sha1, "DSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_1, "ECDSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_224, "ECDSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_256, "ECDSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_384, "ECDSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_512, "ECDSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_RSA_v1_5_SHA_1, "RSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_RSA_v1_5_SHA_256, "RSA");
			addEntries(EACObjectIdentifiers_Fields.id_TA_RSA_PSS_SHA_1, "RSAandMGF1");
			addEntries(EACObjectIdentifiers_Fields.id_TA_RSA_PSS_SHA_256, "RSAandMGF1");

			addEntries(X9ObjectIdentifiers_Fields.id_dsa, "DSA");
			addEntries(PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA");
			addEntries(TeleTrusTObjectIdentifiers_Fields.teleTrusTRSAsignatureAlgorithm, "RSA");
			addEntries(X509ObjectIdentifiers_Fields.id_ea_rsa, "RSA");
			addEntries(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS, "RSAandMGF1");
			addEntries(CryptoProObjectIdentifiers_Fields.gostR3410_94, "GOST3410");
			addEntries(CryptoProObjectIdentifiers_Fields.gostR3410_2001, "ECGOST3410");
			addEntries(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.6.2"), "ECGOST3410");
			addEntries(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.1.5"), "GOST3410");
			addEntries(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_256, "ECGOST3410-2012-256");
			addEntries(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512, "ECGOST3410-2012-512");
			addEntries(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001, "ECGOST3410");
			addEntries(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94, "GOST3410");
			addEntries(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256, "ECGOST3410-2012-256");
			addEntries(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512, "ECGOST3410-2012-512");
		}


		/// <summary>
		/// Return the digest encryption algorithm using one of the standard
		/// JCA string representations rather the the algorithm identifier (if
		/// possible).
		/// </summary>
		public virtual string getEncryptionAlgName(string encryptionAlgOID)
		{
			string algName = (string)encryptionAlgs.get(encryptionAlgOID);

			if (!string.ReferenceEquals(algName, null))
			{
				return algName;
			}

			return encryptionAlgOID;
		}

		public virtual AlgorithmIdentifier fixAlgID(AlgorithmIdentifier algId)
		{
			if (algId.getParameters() == null)
			{
				return new AlgorithmIdentifier(algId.getAlgorithm(), DERNull.INSTANCE);
			}

			return algId;
		}

		public virtual void setSigningEncryptionAlgorithmMapping(ASN1ObjectIdentifier oid, string algorithmName)
		{
			addEntries(oid, algorithmName);
		}

		public virtual Store getCertificates(ASN1Set certSet)
		{
			if (certSet != null)
			{
				List certList = new ArrayList(certSet.size());

				for (Enumeration en = certSet.getObjects(); en.hasMoreElements();)
				{
					ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

					if (obj is ASN1Sequence)
					{
						certList.add(new X509CertificateHolder(Certificate.getInstance(obj)));
					}
				}

				return new CollectionStore(certList);
			}

			return new CollectionStore(new ArrayList());
		}

		public virtual Store getAttributeCertificates(ASN1Set certSet)
		{
			if (certSet != null)
			{
				List certList = new ArrayList(certSet.size());

				for (Enumeration en = certSet.getObjects(); en.hasMoreElements();)
				{
					ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

					if (obj is ASN1TaggedObject)
					{
						certList.add(new X509AttributeCertificateHolder(AttributeCertificate.getInstance(((ASN1TaggedObject)obj).getObject())));
					}
				}

				return new CollectionStore(certList);
			}

			return new CollectionStore(new ArrayList());
		}

		public virtual Store getCRLs(ASN1Set crlSet)
		{
			if (crlSet != null)
			{
				List crlList = new ArrayList(crlSet.size());

				for (Enumeration en = crlSet.getObjects(); en.hasMoreElements();)
				{
					ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

					if (obj is ASN1Sequence)
					{
						crlList.add(new X509CRLHolder(CertificateList.getInstance(obj)));
					}
				}

				return new CollectionStore(crlList);
			}

			return new CollectionStore(new ArrayList());
		}

		public virtual Store getOtherRevocationInfo(ASN1ObjectIdentifier otherRevocationInfoFormat, ASN1Set crlSet)
		{
			if (crlSet != null)
			{
				List crlList = new ArrayList(crlSet.size());

				for (Enumeration en = crlSet.getObjects(); en.hasMoreElements();)
				{
					ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

					if (obj is ASN1TaggedObject)
					{
						ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(obj);

						if (tObj.getTagNo() == 1)
						{
							OtherRevocationInfoFormat other = OtherRevocationInfoFormat.getInstance(tObj, false);

							if (otherRevocationInfoFormat.Equals(other.getInfoFormat()))
							{
								crlList.add(other.getInfo());
							}
						}
					}
				}

				return new CollectionStore(crlList);
			}

			return new CollectionStore(new ArrayList());
		}
	}

}