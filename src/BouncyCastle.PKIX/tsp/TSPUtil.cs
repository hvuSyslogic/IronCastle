using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.gm;

using System;

namespace org.bouncycastle.tsp
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using GMObjectIdentifiers = org.bouncycastle.asn1.gm.GMObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using ExtendedKeyUsage = org.bouncycastle.asn1.x509.ExtendedKeyUsage;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using KeyPurposeId = org.bouncycastle.asn1.x509.KeyPurposeId;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Arrays = org.bouncycastle.util.Arrays;
	using Integers = org.bouncycastle.util.Integers;

	public class TSPUtil
	{
		private static List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());

		private static readonly Map digestLengths = new HashMap();
		private static readonly Map digestNames = new HashMap();

		static TSPUtil()
		{
			digestLengths.put(PKCSObjectIdentifiers_Fields.md5.getId(), Integers.valueOf(16));
			digestLengths.put(OIWObjectIdentifiers_Fields.idSHA1.getId(), Integers.valueOf(20));
			digestLengths.put(NISTObjectIdentifiers_Fields.id_sha224.getId(), Integers.valueOf(28));
			digestLengths.put(NISTObjectIdentifiers_Fields.id_sha256.getId(), Integers.valueOf(32));
			digestLengths.put(NISTObjectIdentifiers_Fields.id_sha384.getId(), Integers.valueOf(48));
			digestLengths.put(NISTObjectIdentifiers_Fields.id_sha512.getId(), Integers.valueOf(64));
			digestLengths.put(TeleTrusTObjectIdentifiers_Fields.ripemd128.getId(), Integers.valueOf(16));
			digestLengths.put(TeleTrusTObjectIdentifiers_Fields.ripemd160.getId(), Integers.valueOf(20));
			digestLengths.put(TeleTrusTObjectIdentifiers_Fields.ripemd256.getId(), Integers.valueOf(32));
			digestLengths.put(CryptoProObjectIdentifiers_Fields.gostR3411.getId(), Integers.valueOf(32));
			digestLengths.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256.getId(), Integers.valueOf(32));
			digestLengths.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512.getId(), Integers.valueOf(64));
			digestLengths.put(GMObjectIdentifiers_Fields.sm3.getId(), Integers.valueOf(32));

			digestNames.put(PKCSObjectIdentifiers_Fields.md5.getId(), "MD5");
			digestNames.put(OIWObjectIdentifiers_Fields.idSHA1.getId(), "SHA1");
			digestNames.put(NISTObjectIdentifiers_Fields.id_sha224.getId(), "SHA224");
			digestNames.put(NISTObjectIdentifiers_Fields.id_sha256.getId(), "SHA256");
			digestNames.put(NISTObjectIdentifiers_Fields.id_sha384.getId(), "SHA384");
			digestNames.put(NISTObjectIdentifiers_Fields.id_sha512.getId(), "SHA512");
			digestNames.put(PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption.getId(), "SHA1");
			digestNames.put(PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption.getId(), "SHA224");
			digestNames.put(PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption.getId(), "SHA256");
			digestNames.put(PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption.getId(), "SHA384");
			digestNames.put(PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption.getId(), "SHA512");
			digestNames.put(TeleTrusTObjectIdentifiers_Fields.ripemd128.getId(), "RIPEMD128");
			digestNames.put(TeleTrusTObjectIdentifiers_Fields.ripemd160.getId(), "RIPEMD160");
			digestNames.put(TeleTrusTObjectIdentifiers_Fields.ripemd256.getId(), "RIPEMD256");
			digestNames.put(CryptoProObjectIdentifiers_Fields.gostR3411.getId(), "GOST3411");
			digestNames.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256.getId(), "GOST3411-2012-256");
			digestNames.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512.getId(), "GOST3411-2012-512");
			digestNames.put(GMObjectIdentifiers_Fields.sm3.getId(), "SM3");
		}

		 /// <summary>
		 /// Fetches the signature time-stamp attributes from a SignerInformation object.
		 /// Checks that the MessageImprint for each time-stamp matches the signature field.
		 /// (see RFC 3161 Appendix A).
		 /// </summary>
		 /// <param name="signerInfo"> a SignerInformation to search for time-stamps </param>
		 /// <param name="digCalcProvider"> provider for digest calculators </param>
		 /// <returns> a collection of TimeStampToken objects </returns>
		 /// <exception cref="TSPValidationException"> </exception>
		public static Collection getSignatureTimestamps(SignerInformation signerInfo, DigestCalculatorProvider digCalcProvider)
		{
			List timestamps = new ArrayList();

			AttributeTable unsignedAttrs = signerInfo.getUnsignedAttributes();
			if (unsignedAttrs != null)
			{
				ASN1EncodableVector allTSAttrs = unsignedAttrs.getAll(PKCSObjectIdentifiers_Fields.id_aa_signatureTimeStampToken);
				for (int i = 0; i < allTSAttrs.size(); ++i)
				{
					Attribute tsAttr = (Attribute)allTSAttrs.get(i);
					ASN1Set tsAttrValues = tsAttr.getAttrValues();
					for (int j = 0; j < tsAttrValues.size(); ++j)
					{
						try
						{
							ContentInfo contentInfo = ContentInfo.getInstance(tsAttrValues.getObjectAt(j));
							TimeStampToken timeStampToken = new TimeStampToken(contentInfo);
							TimeStampTokenInfo tstInfo = timeStampToken.getTimeStampInfo();

							DigestCalculator digCalc = digCalcProvider.get(tstInfo.getHashAlgorithm());

							OutputStream dOut = digCalc.getOutputStream();

							dOut.write(signerInfo.getSignature());
							dOut.close();

							byte[] expectedDigest = digCalc.getDigest();

							if (!Arrays.constantTimeAreEqual(expectedDigest, tstInfo.getMessageImprintDigest()))
							{
								throw new TSPValidationException("Incorrect digest in message imprint");
							}

							timestamps.add(timeStampToken);
						}
						catch (OperatorCreationException)
						{
							throw new TSPValidationException("Unknown hash algorithm specified in timestamp");
						}
						catch (Exception)
						{
							throw new TSPValidationException("Timestamp could not be parsed");
						}
					}
				}
			}

			return timestamps;
		}

		/// <summary>
		/// Validate the passed in certificate as being of the correct type to be used
		/// for time stamping. To be valid it must have an ExtendedKeyUsage extension
		/// which has a key purpose identifier of id-kp-timeStamping.
		/// </summary>
		/// <param name="cert"> the certificate of interest. </param>
		/// <exception cref="TSPValidationException"> if the certificate fails on one of the check points. </exception>
		public static void validateCertificate(X509CertificateHolder cert)
		{
			if (cert.toASN1Structure().getVersionNumber() != 3)
			{
				throw new IllegalArgumentException("Certificate must have an ExtendedKeyUsage extension.");
			}

			Extension ext = cert.getExtension(Extension.extendedKeyUsage);
			if (ext == null)
			{
				throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension.");
			}

			if (!ext.isCritical())
			{
				throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension marked as critical.");
			}

			ExtendedKeyUsage extKey = ExtendedKeyUsage.getInstance(ext.getParsedValue());

			if (!extKey.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping) || extKey.size() != 1)
			{
				throw new TSPValidationException("ExtendedKeyUsage not solely time stamping.");
			}
		}

		internal static int getDigestLength(string digestAlgOID)
		{
			int? length = (int?)digestLengths.get(digestAlgOID);

			if (length != null)
			{
				return length.Value;
			}

			throw new TSPException("digest algorithm cannot be found.");
		}

		internal static List getExtensionOIDs(Extensions extensions)
		{
			if (extensions == null)
			{
				return EMPTY_LIST;
			}

			return Collections.unmodifiableList(java.util.Arrays.asList(extensions.getExtensionOIDs()));
		}

		internal static void addExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier oid, bool isCritical, ASN1Encodable value)
		{
			try
			{
				extGenerator.addExtension(oid, isCritical, value);
			}
			catch (IOException e)
			{
				throw new TSPIOException("cannot encode extension: " + e.Message, e);
			}
		}
	}

}