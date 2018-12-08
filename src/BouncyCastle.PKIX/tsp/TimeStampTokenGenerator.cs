using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.tsp
{

	using ASN1Boolean = org.bouncycastle.asn1.ASN1Boolean;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1GeneralizedTime = org.bouncycastle.asn1.ASN1GeneralizedTime;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using ESSCertID = org.bouncycastle.asn1.ess.ESSCertID;
	using ESSCertIDv2 = org.bouncycastle.asn1.ess.ESSCertIDv2;
	using SigningCertificate = org.bouncycastle.asn1.ess.SigningCertificate;
	using SigningCertificateV2 = org.bouncycastle.asn1.ess.SigningCertificateV2;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Accuracy = org.bouncycastle.asn1.tsp.Accuracy;
	using MessageImprint = org.bouncycastle.asn1.tsp.MessageImprint;
	using TSTInfo = org.bouncycastle.asn1.tsp.TSTInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using IssuerSerial = org.bouncycastle.asn1.x509.IssuerSerial;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using CMSAttributeTableGenerationException = org.bouncycastle.cms.CMSAttributeTableGenerationException;
	using CMSAttributeTableGenerator = org.bouncycastle.cms.CMSAttributeTableGenerator;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSProcessableByteArray = org.bouncycastle.cms.CMSProcessableByteArray;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;
	using CMSSignedDataGenerator = org.bouncycastle.cms.CMSSignedDataGenerator;
	using SignerInfoGenerator = org.bouncycastle.cms.SignerInfoGenerator;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using CollectionStore = org.bouncycastle.util.CollectionStore;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// Currently the class supports ESSCertID by if a digest calculator based on SHA1 is passed in, otherwise it uses
	/// ESSCertIDv2. In the event you need to pass both types, you will need to override the SignedAttributeGenerator
	/// for the SignerInfoGeneratorBuilder you are using. For the default for ESSCertIDv2 the code will look something
	/// like the following:
	/// <pre>
	/// final ESSCertID essCertid = new ESSCertID(certHashSha1, issuerSerial);
	/// final ESSCertIDv2 essCertidV2 = new ESSCertIDv2(certHashSha256, issuerSerial);
	/// 
	/// signerInfoGenBuilder.setSignedAttributeGenerator(new CMSAttributeTableGenerator()
	/// {
	///     public AttributeTable getAttributes(Map parameters)
	///         throws CMSAttributeTableGenerationException
	///     {
	///         CMSAttributeTableGenerator attrGen = new DefaultSignedAttributeTableGenerator();
	/// 
	///         AttributeTable table = attrGen.getAttributes(parameters);
	/// 
	///         table = table.add(PKCSObjectIdentifiers.id_aa_signingCertificate, new SigningCertificate(essCertid));
	///         table = table.add(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new SigningCertificateV2(essCertidV2));
	/// 
	///         return table;
	///     }
	/// });
	/// </pre>
	/// </summary>
	public class TimeStampTokenGenerator
	{
		/// <summary>
		/// Create time-stamps with a resolution of 1 second (the default).
		/// </summary>
		public const int R_SECONDS = 0;

		/// <summary>
		/// Create time-stamps with a resolution of 1 tenth of a second.
		/// </summary>
		public const int R_TENTHS_OF_SECONDS = 1;

		/// <summary>
		/// Create time-stamps with a resolution of 1 microsecond.
		/// </summary>
		public const int R_MICROSECONDS = 2;

		/// <summary>
		/// Create time-stamps with a resolution of 1 millisecond.
		/// </summary>
		public const int R_MILLISECONDS = 3;

		private int resolution = R_SECONDS;
		private Locale locale = null; // default locale

		private int accuracySeconds = -1;

		private int accuracyMillis = -1;

		private int accuracyMicros = -1;

		internal bool ordering = false;

		internal GeneralName tsa = null;

		private ASN1ObjectIdentifier tsaPolicyOID;

		private List certs = new ArrayList();
		private List crls = new ArrayList();
		private List attrCerts = new ArrayList();
		private Map otherRevoc = new HashMap();
		private SignerInfoGenerator signerInfoGen;

		/// <summary>
		/// Basic Constructor - set up a calculator based on signerInfoGen with a ESSCertID calculated from
		/// the signer's associated certificate using the sha1DigestCalculator. If alternate values are required
		/// for id-aa-signingCertificate they should be added to the signerInfoGen object before it is passed in,
		/// otherwise a standard digest based value will be added.
		/// </summary>
		/// <param name="signerInfoGen"> the generator for the signer we are using. </param>
		/// <param name="digestCalculator"> calculator for to use for digest of certificate. </param>
		/// <param name="tsaPolicy"> tasPolicy to send. </param>
		/// <exception cref="IllegalArgumentException"> if calculator is not SHA-1 or there is no associated certificate for the signer, </exception>
		/// <exception cref="TSPException"> if the signer certificate cannot be processed. </exception>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public TimeStampTokenGenerator(final org.bouncycastle.cms.SignerInfoGenerator signerInfoGen, org.bouncycastle.operator.DigestCalculator digestCalculator, org.bouncycastle.asn1.ASN1ObjectIdentifier tsaPolicy) throws IllegalArgumentException, TSPException
		public TimeStampTokenGenerator(SignerInfoGenerator signerInfoGen, DigestCalculator digestCalculator, ASN1ObjectIdentifier tsaPolicy) : this(signerInfoGen, digestCalculator, tsaPolicy, false)
		{
		}

		/// <summary>
		/// Basic Constructor - set up a calculator based on signerInfoGen with a ESSCertID calculated from
		/// the signer's associated certificate using the sha1DigestCalculator. If alternate values are required
		/// for id-aa-signingCertificate they should be added to the signerInfoGen object before it is passed in,
		/// otherwise a standard digest based value will be added.
		/// </summary>
		/// <param name="signerInfoGen"> the generator for the signer we are using. </param>
		/// <param name="digestCalculator"> calculator for to use for digest of certificate. </param>
		/// <param name="tsaPolicy"> tasPolicy to send. </param>
		/// <param name="isIssuerSerialIncluded"> should issuerSerial be included in the ESSCertIDs, true if yes, by default false. </param>
		/// <exception cref="IllegalArgumentException"> if calculator is not SHA-1 or there is no associated certificate for the signer, </exception>
		/// <exception cref="TSPException"> if the signer certificate cannot be processed. </exception>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public TimeStampTokenGenerator(final org.bouncycastle.cms.SignerInfoGenerator signerInfoGen, org.bouncycastle.operator.DigestCalculator digestCalculator, org.bouncycastle.asn1.ASN1ObjectIdentifier tsaPolicy, boolean isIssuerSerialIncluded) throws IllegalArgumentException, TSPException
		public TimeStampTokenGenerator(SignerInfoGenerator signerInfoGen, DigestCalculator digestCalculator, ASN1ObjectIdentifier tsaPolicy, bool isIssuerSerialIncluded)
		{
			this.signerInfoGen = signerInfoGen;
			this.tsaPolicyOID = tsaPolicy;

			if (!signerInfoGen.hasAssociatedCertificate())
			{
				throw new IllegalArgumentException("SignerInfoGenerator must have an associated certificate");
			}

			X509CertificateHolder assocCert = signerInfoGen.getAssociatedCertificate();
			TSPUtil.validateCertificate(assocCert);

			try
			{
				OutputStream dOut = digestCalculator.getOutputStream();

				dOut.write(assocCert.getEncoded());

				dOut.close();

				if (digestCalculator.getAlgorithmIdentifier().getAlgorithm().Equals(OIWObjectIdentifiers_Fields.idSHA1))
				{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ess.ESSCertID essCertid = new org.bouncycastle.asn1.ess.ESSCertID(digestCalculator.getDigest(), isIssuerSerialIncluded ? new org.bouncycastle.asn1.x509.IssuerSerial(new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName(assocCert.getIssuer())), assocCert.getSerialNumber())
					ESSCertID essCertid = new ESSCertID(digestCalculator.getDigest(), isIssuerSerialIncluded ? new IssuerSerial(new GeneralNames(new GeneralName(assocCert.getIssuer())), assocCert.getSerialNumber())
																	   : null);

					this.signerInfoGen = new SignerInfoGenerator(signerInfoGen, new CMSAttributeTableGeneratorAnonymousInnerClass(this, signerInfoGen, essCertid)
				   , signerInfoGen.getUnsignedAttributeTableGenerator());
				}
				else
				{
					AlgorithmIdentifier digAlgID = new AlgorithmIdentifier(digestCalculator.getAlgorithmIdentifier().getAlgorithm());
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ess.ESSCertIDv2 essCertid = new org.bouncycastle.asn1.ess.ESSCertIDv2(digAlgID, digestCalculator.getDigest(), isIssuerSerialIncluded ? new org.bouncycastle.asn1.x509.IssuerSerial(new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName(assocCert.getIssuer())), new org.bouncycastle.asn1.ASN1Integer(assocCert.getSerialNumber()))
					ESSCertIDv2 essCertid = new ESSCertIDv2(digAlgID, digestCalculator.getDigest(), isIssuerSerialIncluded ? new IssuerSerial(new GeneralNames(new GeneralName(assocCert.getIssuer())), new ASN1Integer(assocCert.getSerialNumber()))
																			   : null);

					this.signerInfoGen = new SignerInfoGenerator(signerInfoGen, new CMSAttributeTableGeneratorAnonymousInnerClass2(this, signerInfoGen, essCertid)
				   , signerInfoGen.getUnsignedAttributeTableGenerator());
				}
			}
			catch (IOException e)
			{
				throw new TSPException("Exception processing certificate.", e);
			}
		}

		public class CMSAttributeTableGeneratorAnonymousInnerClass : CMSAttributeTableGenerator
		{
			private readonly TimeStampTokenGenerator outerInstance;

			private SignerInfoGenerator signerInfoGen;
			private ESSCertID essCertid;

			public CMSAttributeTableGeneratorAnonymousInnerClass(TimeStampTokenGenerator outerInstance, SignerInfoGenerator signerInfoGen, ESSCertID essCertid)
			{
				this.outerInstance = outerInstance;
				this.signerInfoGen = signerInfoGen;
				this.essCertid = essCertid;
			}

			public AttributeTable getAttributes(Map parameters)
			{
				AttributeTable table = signerInfoGen.getSignedAttributeTableGenerator().getAttributes(parameters);

				if (table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate) == null)
				{
					return table.add(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate, new SigningCertificate(essCertid));
				}

				return table;
			}
		}

		public class CMSAttributeTableGeneratorAnonymousInnerClass2 : CMSAttributeTableGenerator
		{
			private readonly TimeStampTokenGenerator outerInstance;

			private SignerInfoGenerator signerInfoGen;
			private ESSCertIDv2 essCertid;

			public CMSAttributeTableGeneratorAnonymousInnerClass2(TimeStampTokenGenerator outerInstance, SignerInfoGenerator signerInfoGen, ESSCertIDv2 essCertid)
			{
				this.outerInstance = outerInstance;
				this.signerInfoGen = signerInfoGen;
				this.essCertid = essCertid;
			}

			public AttributeTable getAttributes(Map parameters)
			{
				AttributeTable table = signerInfoGen.getSignedAttributeTableGenerator().getAttributes(parameters);

				if (table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificateV2) == null)
				{
					return table.add(PKCSObjectIdentifiers_Fields.id_aa_signingCertificateV2, new SigningCertificateV2(essCertid));
				}

				return table;
			}
		}

		/// <summary>
		/// Add the store of X509 Certificates to the generator.
		/// </summary>
		/// <param name="certStore">  a Store containing X509CertificateHolder objects </param>
		public virtual void addCertificates(Store certStore)
		{
			certs.addAll(certStore.getMatches(null));
		}

		/// 
		/// <param name="crlStore"> a Store containing X509CRLHolder objects. </param>
		public virtual void addCRLs(Store crlStore)
		{
			crls.addAll(crlStore.getMatches(null));
		}

		/// 
		/// <param name="attrStore"> a Store containing X509AttributeCertificate objects. </param>
		public virtual void addAttributeCertificates(Store attrStore)
		{
			attrCerts.addAll(attrStore.getMatches(null));
		}

		/// <summary>
		/// Add a Store of otherRevocationData to the CRL set to be included with the generated TimeStampToken.
		/// </summary>
		/// <param name="otherRevocationInfoFormat"> the OID specifying the format of the otherRevocationInfo data. </param>
		/// <param name="otherRevocationInfos"> a Store of otherRevocationInfo data to add. </param>
		public virtual void addOtherRevocationInfo(ASN1ObjectIdentifier otherRevocationInfoFormat, Store otherRevocationInfos)
		{
			otherRevoc.put(otherRevocationInfoFormat, otherRevocationInfos.getMatches(null));
		}

		/// <summary>
		/// Set the resolution of the time stamp - R_SECONDS (the default), R_TENTH_OF_SECONDS, R_MICROSECONDS, R_MILLISECONDS
		/// </summary>
		/// <param name="resolution"> resolution of timestamps to be produced. </param>
		public virtual void setResolution(int resolution)
		{
			this.resolution = resolution;
		}

		/// <summary>
		/// Set a Locale for time creation - you may need to use this if the default locale
		/// doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible with other ASN.1 implementations.
		/// </summary>
		/// <param name="locale"> a locale to use for converting system time into a GeneralizedTime. </param>
		public virtual void setLocale(Locale locale)
		{
			this.locale = locale;
		}

		public virtual void setAccuracySeconds(int accuracySeconds)
		{
			this.accuracySeconds = accuracySeconds;
		}

		public virtual void setAccuracyMillis(int accuracyMillis)
		{
			this.accuracyMillis = accuracyMillis;
		}

		public virtual void setAccuracyMicros(int accuracyMicros)
		{
			this.accuracyMicros = accuracyMicros;
		}

		public virtual void setOrdering(bool ordering)
		{
			this.ordering = ordering;
		}

		public virtual void setTSA(GeneralName tsa)
		{
			this.tsa = tsa;
		}

		/// <summary>
		/// Generate a TimeStampToken for the passed in request and serialNumber marking it with the passed in genTime.
		/// </summary>
		/// <param name="request"> the originating request. </param>
		/// <param name="serialNumber"> serial number for the TimeStampToken </param>
		/// <param name="genTime"> token generation time. </param>
		/// <returns> a TimeStampToken </returns>
		/// <exception cref="TSPException"> </exception>
		public virtual TimeStampToken generate(TimeStampRequest request, BigInteger serialNumber, DateTime genTime)
		{
			return generate(request, serialNumber, genTime, null);
		}

		/// <summary>
		/// Generate a TimeStampToken for the passed in request and serialNumber marking it with the passed in genTime.
		/// </summary>
		/// <param name="request"> the originating request. </param>
		/// <param name="serialNumber"> serial number for the TimeStampToken </param>
		/// <param name="genTime"> token generation time. </param>
		/// <param name="additionalExtensions"> extra extensions to be added to the response token. </param>
		/// <returns> a TimeStampToken </returns>
		/// <exception cref="TSPException"> </exception>
		public virtual TimeStampToken generate(TimeStampRequest request, BigInteger serialNumber, DateTime genTime, Extensions additionalExtensions)
		{
			ASN1ObjectIdentifier digestAlgOID = request.getMessageImprintAlgOID();

			AlgorithmIdentifier algID = new AlgorithmIdentifier(digestAlgOID, DERNull.INSTANCE);
			MessageImprint messageImprint = new MessageImprint(algID, request.getMessageImprintDigest());

			Accuracy accuracy = null;
			if (accuracySeconds > 0 || accuracyMillis > 0 || accuracyMicros > 0)
			{
				ASN1Integer seconds = null;
				if (accuracySeconds > 0)
				{
					seconds = new ASN1Integer(accuracySeconds);
				}

				ASN1Integer millis = null;
				if (accuracyMillis > 0)
				{
					millis = new ASN1Integer(accuracyMillis);
				}

				ASN1Integer micros = null;
				if (accuracyMicros > 0)
				{
					micros = new ASN1Integer(accuracyMicros);
				}

				accuracy = new Accuracy(seconds, millis, micros);
			}

			ASN1Boolean derOrdering = null;
			if (ordering)
			{
				derOrdering = ASN1Boolean.getInstance(ordering);
			}

			ASN1Integer nonce = null;
			if (request.getNonce() != null)
			{
				nonce = new ASN1Integer(request.getNonce());
			}

			ASN1ObjectIdentifier tsaPolicy = tsaPolicyOID;
			if (request.getReqPolicy() != null)
			{
				tsaPolicy = request.getReqPolicy();
			}

			Extensions respExtensions = request.getExtensions();
			if (additionalExtensions != null)
			{
				ExtensionsGenerator extGen = new ExtensionsGenerator();

				if (respExtensions != null)
				{
					for (Enumeration en = respExtensions.oids(); en.hasMoreElements();)
					{
						extGen.addExtension(respExtensions.getExtension(ASN1ObjectIdentifier.getInstance(en.nextElement())));
					}
				}
				for (Enumeration en = additionalExtensions.oids(); en.hasMoreElements();)
				{
					extGen.addExtension(additionalExtensions.getExtension(ASN1ObjectIdentifier.getInstance(en.nextElement())));
				}

				respExtensions = extGen.generate();
			}

			ASN1GeneralizedTime timeStampTime;
			if (resolution == R_SECONDS)
			{
				timeStampTime = (locale == null) ? new ASN1GeneralizedTime(genTime) : new ASN1GeneralizedTime(genTime, locale);
			}
			else
			{
				timeStampTime = createGeneralizedTime(genTime);
			}

			TSTInfo tstInfo = new TSTInfo(tsaPolicy, messageImprint, new ASN1Integer(serialNumber), timeStampTime, accuracy, derOrdering, nonce, tsa, respExtensions);

			try
			{
				CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

				if (request.getCertReq())
				{
					// TODO: do we need to check certs non-empty?
					signedDataGenerator.addCertificates(new CollectionStore(certs));
					signedDataGenerator.addAttributeCertificates(new CollectionStore(attrCerts));
				}

				signedDataGenerator.addCRLs(new CollectionStore(crls));

				if (!otherRevoc.isEmpty())
				{
					for (Iterator it = otherRevoc.keySet().iterator(); it.hasNext();)
					{
						ASN1ObjectIdentifier format = (ASN1ObjectIdentifier)it.next();

						signedDataGenerator.addOtherRevocationInfo(format, new CollectionStore((Collection)otherRevoc.get(format)));
					}
				}

				signedDataGenerator.addSignerInfoGenerator(signerInfoGen);

				byte[] derEncodedTSTInfo = tstInfo.getEncoded(ASN1Encoding_Fields.DER);

				CMSSignedData signedData = signedDataGenerator.generate(new CMSProcessableByteArray(PKCSObjectIdentifiers_Fields.id_ct_TSTInfo, derEncodedTSTInfo), true);

				return new TimeStampToken(signedData);
			}
			catch (CMSException cmsEx)
			{
				throw new TSPException("Error generating time-stamp token", cmsEx);
			}
			catch (IOException e)
			{
				throw new TSPException("Exception encoding info", e);
			}
		}

		// we need to produce a correct DER encoding GeneralizedTime here as the BC ASN.1 library doesn't handle this properly yet.
		private ASN1GeneralizedTime createGeneralizedTime(DateTime time)
		{
			string format = "yyyyMMddHHmmss.SSS";
			SimpleDateFormat dateF = (locale == null) ? new SimpleDateFormat(format) : new SimpleDateFormat(format, locale);
			dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
			StringBuilder sBuild = new StringBuilder(dateF.format(time));
			int dotIndex = sBuild.indexOf(".");

			if (dotIndex < 0)
			{
				// came back in seconds only, just return
				sBuild.append("Z");
				return new ASN1GeneralizedTime(sBuild.ToString());
			}

			// trim to resolution
			switch (resolution)
			{
			case R_TENTHS_OF_SECONDS:
				if (sBuild.length() > dotIndex + 2)
				{
					sBuild.delete(dotIndex + 2, sBuild.length());
				}
				break;
			case R_MICROSECONDS:
				if (sBuild.length() > dotIndex + 3)
				{
					sBuild.delete(dotIndex + 3, sBuild.length());
				}
				break;
			case R_MILLISECONDS:
				// do nothing
				break;
			default:
				throw new TSPException("unknown time-stamp resolution: " + resolution);
			}

			// remove trailing zeros
			while (sBuild.charAt(sBuild.length() - 1) == '0')
			{
				sBuild.deleteCharAt(sBuild.length() - 1);
			}

			if (sBuild.length() - 1 == dotIndex)
			{
				sBuild.deleteCharAt(sBuild.length() - 1);
			}

			sBuild.append("Z");

			return new ASN1GeneralizedTime(sBuild.ToString());
		}
	}

}