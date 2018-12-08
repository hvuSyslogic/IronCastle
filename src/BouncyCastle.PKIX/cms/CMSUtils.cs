using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.sec;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using BEROctetStringGenerator = org.bouncycastle.asn1.BEROctetStringGenerator;
	using BERSet = org.bouncycastle.asn1.BERSet;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using OtherRevocationInfoFormat = org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using OCSPResponse = org.bouncycastle.asn1.ocsp.OCSPResponse;
	using OCSPResponseStatus = org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using SECObjectIdentifiers = org.bouncycastle.asn1.sec.SECObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using X509AttributeCertificateHolder = org.bouncycastle.cert.X509AttributeCertificateHolder;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using Store = org.bouncycastle.util.Store;
	using Strings = org.bouncycastle.util.Strings;
	using Streams = org.bouncycastle.util.io.Streams;
	using TeeInputStream = org.bouncycastle.util.io.TeeInputStream;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	public class CMSUtils
	{
		private static readonly Set<string> des = new HashSet<string>();
		private static readonly Set mqvAlgs = new HashSet();
		private static readonly Set ecAlgs = new HashSet();
		private static readonly Set gostAlgs = new HashSet();

		static CMSUtils()
		{
			des.add("DES");
			des.add("DESEDE");
			des.add(OIWObjectIdentifiers_Fields.desCBC.getId());
			des.add(PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId());
			des.add(PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId());
			des.add(PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap.getId());

			mqvAlgs.add(X9ObjectIdentifiers_Fields.mqvSinglePass_sha1kdf_scheme);
			mqvAlgs.add(SECObjectIdentifiers_Fields.mqvSinglePass_sha224kdf_scheme);
			mqvAlgs.add(SECObjectIdentifiers_Fields.mqvSinglePass_sha256kdf_scheme);
			mqvAlgs.add(SECObjectIdentifiers_Fields.mqvSinglePass_sha384kdf_scheme);
			mqvAlgs.add(SECObjectIdentifiers_Fields.mqvSinglePass_sha512kdf_scheme);

			ecAlgs.add(X9ObjectIdentifiers_Fields.dhSinglePass_cofactorDH_sha1kdf_scheme);
			ecAlgs.add(X9ObjectIdentifiers_Fields.dhSinglePass_stdDH_sha1kdf_scheme);
			ecAlgs.add(SECObjectIdentifiers_Fields.dhSinglePass_cofactorDH_sha224kdf_scheme);
			ecAlgs.add(SECObjectIdentifiers_Fields.dhSinglePass_stdDH_sha224kdf_scheme);
			ecAlgs.add(SECObjectIdentifiers_Fields.dhSinglePass_cofactorDH_sha256kdf_scheme);
			ecAlgs.add(SECObjectIdentifiers_Fields.dhSinglePass_stdDH_sha256kdf_scheme);
			ecAlgs.add(SECObjectIdentifiers_Fields.dhSinglePass_cofactorDH_sha384kdf_scheme);
			ecAlgs.add(SECObjectIdentifiers_Fields.dhSinglePass_stdDH_sha384kdf_scheme);
			ecAlgs.add(SECObjectIdentifiers_Fields.dhSinglePass_cofactorDH_sha512kdf_scheme);
			ecAlgs.add(SECObjectIdentifiers_Fields.dhSinglePass_stdDH_sha512kdf_scheme);

			gostAlgs.add(CryptoProObjectIdentifiers_Fields.gostR3410_2001_CryptoPro_ESDH);
			gostAlgs.add(RosstandartObjectIdentifiers_Fields.id_tc26_agreement_gost_3410_12_256);
			gostAlgs.add(RosstandartObjectIdentifiers_Fields.id_tc26_agreement_gost_3410_12_512);
		}

		internal static bool isMQV(ASN1ObjectIdentifier algorithm)
		{
			return mqvAlgs.contains(algorithm);
		}

		internal static bool isEC(ASN1ObjectIdentifier algorithm)
		{
			return ecAlgs.contains(algorithm);
		}

		internal static bool isGOST(ASN1ObjectIdentifier algorithm)
		{
			return gostAlgs.contains(algorithm);
		}

		internal static bool isRFC2631(ASN1ObjectIdentifier algorithm)
		{
			return algorithm.Equals(PKCSObjectIdentifiers_Fields.id_alg_ESDH) || algorithm.Equals(PKCSObjectIdentifiers_Fields.id_alg_SSDH);
		}

		internal static bool isDES(string algorithmID)
		{
			string name = Strings.toUpperCase(algorithmID);

			return des.contains(name);
		}

		internal static bool isEquivalent(AlgorithmIdentifier algId1, AlgorithmIdentifier algId2)
		{
			if (algId1 == null || algId2 == null)
			{
				return false;
			}

			if (!algId1.getAlgorithm().Equals(algId2.getAlgorithm()))
			{
				return false;
			}

			ASN1Encodable params1 = algId1.getParameters();
			ASN1Encodable params2 = algId2.getParameters();
			if (params1 != null)
			{
				return params1.Equals(params2) || (params1.Equals(DERNull.INSTANCE) && params2 == null);
			}

			return params2 == null || params2.Equals(DERNull.INSTANCE);
		}

		internal static ContentInfo readContentInfo(byte[] input)
		{
			// enforce limit checking as from a byte array
			return readContentInfo(new ASN1InputStream(input));
		}

		internal static ContentInfo readContentInfo(InputStream input)
		{
			// enforce some limit checking
			return readContentInfo(new ASN1InputStream(input));
		}

		internal static List getCertificatesFromStore(Store certStore)
		{
			List certs = new ArrayList();

			try
			{
				for (Iterator it = certStore.getMatches(null).iterator(); it.hasNext();)
				{
					X509CertificateHolder c = (X509CertificateHolder)it.next();

					certs.add(c.toASN1Structure());
				}

				return certs;
			}
			catch (ClassCastException e)
			{
				throw new CMSException("error processing certs", e);
			}
		}

		internal static List getAttributeCertificatesFromStore(Store attrStore)
		{
			List certs = new ArrayList();

			try
			{
				for (Iterator it = attrStore.getMatches(null).iterator(); it.hasNext();)
				{
					X509AttributeCertificateHolder attrCert = (X509AttributeCertificateHolder)it.next();

					certs.add(new DERTaggedObject(false, 2, attrCert.toASN1Structure()));
				}

				return certs;
			}
			catch (ClassCastException e)
			{
				throw new CMSException("error processing certs", e);
			}
		}


		internal static List getCRLsFromStore(Store crlStore)
		{
			List crls = new ArrayList();

			try
			{
				for (Iterator it = crlStore.getMatches(null).iterator(); it.hasNext();)
				{
					object rev = it.next();

					if (rev is X509CRLHolder)
					{
						X509CRLHolder c = (X509CRLHolder)rev;

						crls.add(c.toASN1Structure());
					}
					else if (rev is OtherRevocationInfoFormat)
					{
						OtherRevocationInfoFormat infoFormat = OtherRevocationInfoFormat.getInstance(rev);

						validateInfoFormat(infoFormat);

						crls.add(new DERTaggedObject(false, 1, infoFormat));
					}
					else if (rev is ASN1TaggedObject)
					{
						crls.add(rev);
					}
				}

				return crls;
			}
			catch (ClassCastException e)
			{
				throw new CMSException("error processing certs", e);
			}
		}

		private static void validateInfoFormat(OtherRevocationInfoFormat infoFormat)
		{
			if (CMSObjectIdentifiers_Fields.id_ri_ocsp_response.Equals(infoFormat.getInfoFormat()))
			{
				OCSPResponse resp = OCSPResponse.getInstance(infoFormat.getInfo());

				if (resp.getResponseStatus().getValue().intValue() != OCSPResponseStatus.SUCCESSFUL)
				{
					throw new IllegalArgumentException("cannot add unsuccessful OCSP response to CMS SignedData");
				}
			}
		}

		internal static Collection getOthersFromStore(ASN1ObjectIdentifier otherRevocationInfoFormat, Store otherRevocationInfos)
		{
			List others = new ArrayList();

			for (Iterator it = otherRevocationInfos.getMatches(null).iterator(); it.hasNext();)
			{
				ASN1Encodable info = (ASN1Encodable)it.next();
				OtherRevocationInfoFormat infoFormat = new OtherRevocationInfoFormat(otherRevocationInfoFormat, info);

				validateInfoFormat(infoFormat);

				others.add(new DERTaggedObject(false, 1, infoFormat));
			}

			return others;
		}

		internal static ASN1Set createBerSetFromList(List derObjects)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (Iterator it = derObjects.iterator(); it.hasNext();)
			{
				v.add((ASN1Encodable)it.next());
			}

			return new BERSet(v);
		}

		internal static ASN1Set createDerSetFromList(List derObjects)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (Iterator it = derObjects.iterator(); it.hasNext();)
			{
				v.add((ASN1Encodable)it.next());
			}

			return new DERSet(v);
		}

		internal static OutputStream createBEROctetOutputStream(OutputStream s, int tagNo, bool isExplicit, int bufferSize)
		{
			BEROctetStringGenerator octGen = new BEROctetStringGenerator(s, tagNo, isExplicit);

			if (bufferSize != 0)
			{
				return octGen.getOctetOutputStream(new byte[bufferSize]);
			}

			return octGen.getOctetOutputStream();
		}

		private static ContentInfo readContentInfo(ASN1InputStream @in)
		{
			try
			{
				ContentInfo info = ContentInfo.getInstance(@in.readObject());
				if (info == null)
				{
					throw new CMSException("No content found.");
				}

				return info;
			}
			catch (IOException e)
			{
				throw new CMSException("IOException reading content.", e);
			}
			catch (ClassCastException e)
			{
				throw new CMSException("Malformed content.", e);
			}
			catch (IllegalArgumentException e)
			{
				throw new CMSException("Malformed content.", e);
			}
		}

		public static byte[] streamToByteArray(InputStream @in)
		{
			return Streams.readAll(@in);
		}

		public static byte[] streamToByteArray(InputStream @in, int limit)
		{
			return Streams.readAllLimited(@in, limit);
		}

		internal static InputStream attachDigestsToInputStream(Collection digests, InputStream s)
		{
			InputStream result = s;
			Iterator it = digests.iterator();
			while (it.hasNext())
			{
				DigestCalculator digest = (DigestCalculator)it.next();
				result = new TeeInputStream(result, digest.getOutputStream());
			}
			return result;
		}

		internal static OutputStream attachSignersToOutputStream(Collection signers, OutputStream s)
		{
			OutputStream result = s;
			Iterator it = signers.iterator();
			while (it.hasNext())
			{
				SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();
				result = getSafeTeeOutputStream(result, signerGen.getCalculatingOutputStream());
			}
			return result;
		}

		internal static OutputStream getSafeOutputStream(OutputStream s)
		{
			return s == null ? new NullOutputStream() : s;
		}

		internal static OutputStream getSafeTeeOutputStream(OutputStream s1, OutputStream s2)
		{
			return s1 == null ? getSafeOutputStream(s2) : s2 == null ? getSafeOutputStream(s1) : new TeeOutputStream(s1, s2);
		}
	}

}