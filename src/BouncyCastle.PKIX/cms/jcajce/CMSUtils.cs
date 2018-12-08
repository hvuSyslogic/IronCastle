using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.sec;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.cms.jcajce
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using SECObjectIdentifiers = org.bouncycastle.asn1.sec.SECObjectIdentifiers;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using AlgorithmParametersUtils = org.bouncycastle.jcajce.util.AlgorithmParametersUtils;

	public class CMSUtils
	{
		private static readonly Set mqvAlgs = new HashSet();
		private static readonly Set ecAlgs = new HashSet();
		private static readonly Set gostAlgs = new HashSet();

		static CMSUtils()
		{
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
			gostAlgs.add(CryptoProObjectIdentifiers_Fields.gostR3410_2001);
			gostAlgs.add(RosstandartObjectIdentifiers_Fields.id_tc26_agreement_gost_3410_12_256);
			gostAlgs.add(RosstandartObjectIdentifiers_Fields.id_tc26_agreement_gost_3410_12_512);
			gostAlgs.add(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_256);
			gostAlgs.add(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512);
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

		internal static IssuerAndSerialNumber getIssuerAndSerialNumber(X509Certificate cert)
		{
			Certificate certStruct = Certificate.getInstance(cert.getEncoded());

			return new IssuerAndSerialNumber(certStruct.getIssuer(), cert.getSerialNumber());
		}

		internal static byte[] getSubjectKeyId(X509Certificate cert)
		{
			byte[] ext = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());

			if (ext != null)
			{
				return ASN1OctetString.getInstance(ASN1OctetString.getInstance(ext).getOctets()).getOctets();
			}
			else
			{
				return null;
			}
		}

		internal static EnvelopedDataHelper createContentHelper(Provider provider)
		{
			if (provider != null)
			{
				return new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
			}
			else
			{
				return new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
			}
		}

		internal static EnvelopedDataHelper createContentHelper(string providerName)
		{
			if (!string.ReferenceEquals(providerName, null))
			{
				return new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
			}
			else
			{
				return new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
			}
		}

		internal static ASN1Encodable extractParameters(AlgorithmParameters @params)
		{
			try
			{
				return AlgorithmParametersUtils.extractParameters(@params);
			}
			catch (IOException e)
			{
				throw new CMSException("cannot extract parameters: " + e.Message, e);
			}
		}

		internal static void loadParameters(AlgorithmParameters @params, ASN1Encodable sParams)
		{
			try
			{
				AlgorithmParametersUtils.loadParameters(@params, sParams);
			}
			catch (IOException e)
			{
				throw new CMSException("error encoding algorithm parameters.", e);
			}
		}
	}
}