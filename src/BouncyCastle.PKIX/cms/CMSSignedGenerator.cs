using org.bouncycastle.asn1.cms;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.rosstandart;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using OtherRevocationInfoFormat = org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using X509AttributeCertificateHolder = org.bouncycastle.cert.X509AttributeCertificateHolder;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using Arrays = org.bouncycastle.util.Arrays;
	using Store = org.bouncycastle.util.Store;

	public class CMSSignedGenerator
	{
		/// <summary>
		/// Default type for the signed data.
		/// </summary>
		public static readonly string DATA = CMSObjectIdentifiers_Fields.data.getId();

		public static readonly string DIGEST_SHA1 = OIWObjectIdentifiers_Fields.idSHA1.getId();
		public static readonly string DIGEST_SHA224 = NISTObjectIdentifiers_Fields.id_sha224.getId();
		public static readonly string DIGEST_SHA256 = NISTObjectIdentifiers_Fields.id_sha256.getId();
		public static readonly string DIGEST_SHA384 = NISTObjectIdentifiers_Fields.id_sha384.getId();
		public static readonly string DIGEST_SHA512 = NISTObjectIdentifiers_Fields.id_sha512.getId();
		public static readonly string DIGEST_MD5 = PKCSObjectIdentifiers_Fields.md5.getId();
		public static readonly string DIGEST_GOST3411 = CryptoProObjectIdentifiers_Fields.gostR3411.getId();
		public static readonly string DIGEST_RIPEMD128 = TeleTrusTObjectIdentifiers_Fields.ripemd128.getId();
		public static readonly string DIGEST_RIPEMD160 = TeleTrusTObjectIdentifiers_Fields.ripemd160.getId();
		public static readonly string DIGEST_RIPEMD256 = TeleTrusTObjectIdentifiers_Fields.ripemd256.getId();

		public static readonly string ENCRYPTION_RSA = PKCSObjectIdentifiers_Fields.rsaEncryption.getId();
		public static readonly string ENCRYPTION_DSA = X9ObjectIdentifiers_Fields.id_dsa_with_sha1.getId();
		public static readonly string ENCRYPTION_ECDSA = X9ObjectIdentifiers_Fields.ecdsa_with_SHA1.getId();
		public static readonly string ENCRYPTION_RSA_PSS = PKCSObjectIdentifiers_Fields.id_RSASSA_PSS.getId();
		public static readonly string ENCRYPTION_GOST3410 = CryptoProObjectIdentifiers_Fields.gostR3410_94.getId();
		public static readonly string ENCRYPTION_ECGOST3410 = CryptoProObjectIdentifiers_Fields.gostR3410_2001.getId();
		public static readonly string ENCRYPTION_ECGOST3410_2012_256 = RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_256.getId();
		public static readonly string ENCRYPTION_ECGOST3410_2012_512 = RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512.getId();

		private static readonly string ENCRYPTION_ECDSA_WITH_SHA1 = X9ObjectIdentifiers_Fields.ecdsa_with_SHA1.getId();
		private static readonly string ENCRYPTION_ECDSA_WITH_SHA224 = X9ObjectIdentifiers_Fields.ecdsa_with_SHA224.getId();
		private static readonly string ENCRYPTION_ECDSA_WITH_SHA256 = X9ObjectIdentifiers_Fields.ecdsa_with_SHA256.getId();
		private static readonly string ENCRYPTION_ECDSA_WITH_SHA384 = X9ObjectIdentifiers_Fields.ecdsa_with_SHA384.getId();
		private static readonly string ENCRYPTION_ECDSA_WITH_SHA512 = X9ObjectIdentifiers_Fields.ecdsa_with_SHA512.getId();

		private static readonly Set NO_PARAMS = new HashSet();
		private static readonly Map EC_ALGORITHMS = new HashMap();

		static CMSSignedGenerator()
		{
			NO_PARAMS.add(ENCRYPTION_DSA);
			NO_PARAMS.add(ENCRYPTION_ECDSA);
			NO_PARAMS.add(ENCRYPTION_ECDSA_WITH_SHA1);
			NO_PARAMS.add(ENCRYPTION_ECDSA_WITH_SHA224);
			NO_PARAMS.add(ENCRYPTION_ECDSA_WITH_SHA256);
			NO_PARAMS.add(ENCRYPTION_ECDSA_WITH_SHA384);
			NO_PARAMS.add(ENCRYPTION_ECDSA_WITH_SHA512);

			EC_ALGORITHMS.put(DIGEST_SHA1, ENCRYPTION_ECDSA_WITH_SHA1);
			EC_ALGORITHMS.put(DIGEST_SHA224, ENCRYPTION_ECDSA_WITH_SHA224);
			EC_ALGORITHMS.put(DIGEST_SHA256, ENCRYPTION_ECDSA_WITH_SHA256);
			EC_ALGORITHMS.put(DIGEST_SHA384, ENCRYPTION_ECDSA_WITH_SHA384);
			EC_ALGORITHMS.put(DIGEST_SHA512, ENCRYPTION_ECDSA_WITH_SHA512);
		}

		protected internal List certs = new ArrayList();
		protected internal List crls = new ArrayList();
		protected internal List _signers = new ArrayList();
		protected internal List signerGens = new ArrayList();
		protected internal Map digests = new HashMap();

		/// <summary>
		/// base constructor
		/// </summary>
		public CMSSignedGenerator()
		{
		}

		public virtual Map getBaseParameters(ASN1ObjectIdentifier contentType, AlgorithmIdentifier digAlgId, byte[] hash)
		{
			Map param = new HashMap();
			param.put(CMSAttributeTableGenerator_Fields.CONTENT_TYPE, contentType);
			param.put(CMSAttributeTableGenerator_Fields.DIGEST_ALGORITHM_IDENTIFIER, digAlgId);
			param.put(CMSAttributeTableGenerator_Fields.DIGEST, Arrays.clone(hash));
			return param;
		}

		/// <summary>
		/// Add a certificate to the certificate set to be included with the generated SignedData message.
		/// </summary>
		/// <param name="certificate"> the certificate to be included. </param>
		/// <exception cref="CMSException"> if the certificate cannot be encoded for adding. </exception>
		public virtual void addCertificate(X509CertificateHolder certificate)
		{
			certs.add(certificate.toASN1Structure());
		}

		/// <summary>
		/// Add the certificates in certStore to the certificate set to be included with the generated SignedData message.
		/// </summary>
		/// <param name="certStore"> the store containing the certificates to be included. </param>
		/// <exception cref="CMSException"> if the certificates cannot be encoded for adding. </exception>
		public virtual void addCertificates(Store certStore)
		{
			certs.addAll(CMSUtils.getCertificatesFromStore(certStore));
		}

		/// <summary>
		/// Add a CRL to the CRL set to be included with the generated SignedData message.
		/// </summary>
		/// <param name="crl"> the CRL to be included. </param>
		public virtual void addCRL(X509CRLHolder crl)
		{
			crls.add(crl.toASN1Structure());
		}

		/// <summary>
		/// Add the CRLs in crlStore to the CRL set to be included with the generated SignedData message.
		/// </summary>
		/// <param name="crlStore"> the store containing the CRLs to be included. </param>
		/// <exception cref="CMSException"> if the CRLs cannot be encoded for adding. </exception>
		public virtual void addCRLs(Store crlStore)
		{
			crls.addAll(CMSUtils.getCRLsFromStore(crlStore));
		}

		/// <summary>
		/// Add the attribute certificates in attrStore to the certificate set to be included with the generated SignedData message.
		/// </summary>
		/// <param name="attrCert"> the store containing the certificates to be included. </param>
		/// <exception cref="CMSException"> if the attribute certificate cannot be encoded for adding. </exception>
		public virtual void addAttributeCertificate(X509AttributeCertificateHolder attrCert)
		{
			certs.add(new DERTaggedObject(false, 2, attrCert.toASN1Structure()));
		}

		/// <summary>
		/// Add the attribute certificates in attrStore to the certificate set to be included with the generated SignedData message.
		/// </summary>
		/// <param name="attrStore"> the store containing the certificates to be included. </param>
		/// <exception cref="CMSException"> if the attribute certificate cannot be encoded for adding. </exception>
		public virtual void addAttributeCertificates(Store attrStore)
		{
			certs.addAll(CMSUtils.getAttributeCertificatesFromStore(attrStore));
		}

		/// <summary>
		/// Add a single instance of otherRevocationData to the CRL set to be included with the generated SignedData message.
		/// </summary>
		/// <param name="otherRevocationInfoFormat"> the OID specifying the format of the otherRevocationInfo data. </param>
		/// <param name="otherRevocationInfo"> the otherRevocationInfo ASN.1 structure. </param>
		public virtual void addOtherRevocationInfo(ASN1ObjectIdentifier otherRevocationInfoFormat, ASN1Encodable otherRevocationInfo)
		{
			crls.add(new DERTaggedObject(false, 1, new OtherRevocationInfoFormat(otherRevocationInfoFormat, otherRevocationInfo)));
		}

		/// <summary>
		/// Add a Store of otherRevocationData to the CRL set to be included with the generated SignedData message.
		/// </summary>
		/// <param name="otherRevocationInfoFormat"> the OID specifying the format of the otherRevocationInfo data. </param>
		/// <param name="otherRevocationInfos"> a Store of otherRevocationInfo data to add. </param>
		public virtual void addOtherRevocationInfo(ASN1ObjectIdentifier otherRevocationInfoFormat, Store otherRevocationInfos)
		{
			crls.addAll(CMSUtils.getOthersFromStore(otherRevocationInfoFormat, otherRevocationInfos));
		}

		/// <summary>
		/// Add a store of pre-calculated signers to the generator.
		/// </summary>
		/// <param name="signerStore"> store of signers </param>
		public virtual void addSigners(SignerInformationStore signerStore)
		{
			Iterator it = signerStore.getSigners().iterator();

			while (it.hasNext())
			{
				_signers.add(it.next());
			}
		}

		/// <summary>
		/// Add a generator for a particular signer to this CMS SignedData generator.
		/// </summary>
		/// <param name="infoGen"> the generator representing the particular signer. </param>
		public virtual void addSignerInfoGenerator(SignerInfoGenerator infoGen)
		{
			 signerGens.add(infoGen);
		}

		/// <summary>
		/// Return a map of oids and byte arrays representing the digests calculated on the content during
		/// the last generate.
		/// </summary>
		/// <returns> a map of oids (as String objects) and byte[] representing digests. </returns>
		public virtual Map getGeneratedDigests()
		{
			return new HashMap(digests);
		}
	}

}