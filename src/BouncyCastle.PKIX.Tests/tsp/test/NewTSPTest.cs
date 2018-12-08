using org.bouncycastle.tsp;
using org.bouncycastle.asn1;
using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.tsp.test
{

	using TestCase = junit.framework.TestCase;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERUTF8String = org.bouncycastle.asn1.DERUTF8String;
	using PKIFailureInfo = org.bouncycastle.asn1.cmp.PKIFailureInfo;
	using PKIStatus = org.bouncycastle.asn1.cmp.PKIStatus;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using ESSCertID = org.bouncycastle.asn1.ess.ESSCertID;
	using ESSCertIDv2 = org.bouncycastle.asn1.ess.ESSCertIDv2;
	using SigningCertificate = org.bouncycastle.asn1.ess.SigningCertificate;
	using SigningCertificateV2 = org.bouncycastle.asn1.ess.SigningCertificateV2;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using ExtendedKeyUsage = org.bouncycastle.asn1.x509.ExtendedKeyUsage;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using IssuerSerial = org.bouncycastle.asn1.x509.IssuerSerial;
	using KeyPurposeId = org.bouncycastle.asn1.x509.KeyPurposeId;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaCertStore = org.bouncycastle.cert.jcajce.JcaCertStore;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using JcaX509v3CertificateBuilder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
	using CMSAttributeTableGenerationException = org.bouncycastle.cms.CMSAttributeTableGenerationException;
	using CMSAttributeTableGenerator = org.bouncycastle.cms.CMSAttributeTableGenerator;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;
	using DefaultSignedAttributeTableGenerator = org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
	using JcaSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
	using JcaSimpleSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using CMSTestUtil = org.bouncycastle.cms.test.CMSTestUtil;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveGenParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using JcaContentSignerBuilder = org.bouncycastle.@operator.jcajce.JcaContentSignerBuilder;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;
	using Arrays = org.bouncycastle.util.Arrays;
	using Store = org.bouncycastle.util.Store;

	public class NewTSPTest : TestCase
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		public virtual void setUp()
		{
			Security.addProvider(new BouncyCastleProvider());
		}

		public virtual void testGeneral()
		{
			string signDN = "O=Bouncy Castle, C=AU";
			KeyPair signKP = TSPTestUtil.makeKeyPair();
			X509Certificate signCert = TSPTestUtil.makeCACertificate(signKP, signDN, signKP, signDN);

			string origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
			KeyPair origKP = TSPTestUtil.makeKeyPair();
			X509Certificate origCert = TSPTestUtil.makeCertificate(origKP, origDN, signKP, signDN);


			List certList = new ArrayList();
			certList.add(origCert);
			certList.add(signCert);

			Store certs = new JcaCertStore(certList);

			basicTest(origKP.getPrivate(), origCert, certs);
			resolutionTest(origKP.getPrivate(), origCert, certs, TimeStampTokenGenerator.R_SECONDS, "19700101000009Z");
			resolutionTest(origKP.getPrivate(), origCert, certs, TimeStampTokenGenerator.R_TENTHS_OF_SECONDS, "19700101000009.9Z");
			resolutionTest(origKP.getPrivate(), origCert, certs, TimeStampTokenGenerator.R_MICROSECONDS, "19700101000009.99Z");
			resolutionTest(origKP.getPrivate(), origCert, certs, TimeStampTokenGenerator.R_MILLISECONDS, "19700101000009.999Z");
			basicSha256Test(origKP.getPrivate(), origCert, certs);
			basicTestWithTSA(origKP.getPrivate(), origCert, certs);
			overrideAttrsTest(origKP.getPrivate(), origCert, certs);
			responseValidationTest(origKP.getPrivate(), origCert, certs);
			incorrectHashTest(origKP.getPrivate(), origCert, certs);
			badAlgorithmTest(origKP.getPrivate(), origCert, certs);
			timeNotAvailableTest(origKP.getPrivate(), origCert, certs);
			badPolicyTest(origKP.getPrivate(), origCert, certs);
			tokenEncodingTest(origKP.getPrivate(), origCert, certs);
			certReqTest(origKP.getPrivate(), origCert, certs);
			testAccuracyZeroCerts(origKP.getPrivate(), origCert, certs);
			testAccuracyWithCertsAndOrdering(origKP.getPrivate(), origCert, certs);
			testNoNonse(origKP.getPrivate(), origCert, certs);
			extensionTest(origKP.getPrivate(), origCert, certs);
			additionalExtensionTest(origKP.getPrivate(), origCert, certs);
		}

		public virtual void testCertOrdering()
		{
			List certList = new ArrayList();

			string _origDN = "O=Bouncy Castle, C=AU";
			KeyPair _origKP = CMSTestUtil.makeKeyPair();
			X509Certificate _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

			string _signDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
			KeyPair _signKP = CMSTestUtil.makeKeyPair();
			X509Certificate _signCert = TSPTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);

			KeyPair _signDsaKP = CMSTestUtil.makeDsaKeyPair();
			X509Certificate _signDsaCert = CMSTestUtil.makeCertificate(_signDsaKP, _signDN, _origKP, _origDN);

			certList.add(_origCert);
			certList.add(_signDsaCert);
			certList.add(_signCert);

			Store certs = new JcaCertStore(certList);

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).build("SHA1withRSA", _signKP.getPrivate(), _signCert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

			reqGen.setCertReq(true);

			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse initResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), DateTime.Now);

			// original CMS SignedData object
			CMSSignedData sd = initResp.getTimeStampToken().toCMSSignedData();

			certs = sd.getCertificates();
			Iterator it = certs.getMatches(null).iterator();

			assertEquals(new JcaX509CertificateHolder(_origCert), it.next());
			assertEquals(new JcaX509CertificateHolder(_signDsaCert), it.next());
			assertEquals(new JcaX509CertificateHolder(_signCert), it.next());

			// definite-length
			TimeStampResponse dlResp = new TimeStampResponse(initResp.getEncoded(ASN1Encoding_Fields.DL));

			sd = dlResp.getTimeStampToken().toCMSSignedData();

			certs = sd.getCertificates();
			it = certs.getMatches(null).iterator();

			assertEquals(new JcaX509CertificateHolder(_origCert), it.next());
			assertEquals(new JcaX509CertificateHolder(_signDsaCert), it.next());
			assertEquals(new JcaX509CertificateHolder(_signCert), it.next());

			// convert to DER - the default encoding
			TimeStampResponse derResp = new TimeStampResponse(initResp.getEncoded());

			sd = derResp.getTimeStampToken().toCMSSignedData();

			certs = sd.getCertificates();
			it = certs.getMatches(null).iterator();

			assertEquals(new JcaX509CertificateHolder(_origCert), it.next());
			assertEquals(new JcaX509CertificateHolder(_signCert), it.next());
			assertEquals(new JcaX509CertificateHolder(_signDsaCert), it.next());
		}

		private void basicTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(cert));

			AttributeTable table = tsToken.getSignedAttributes();

			assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate));
		}

		public virtual void testSM2withSM3()
		{
			//
			 // set up the keys
			 //
			 PrivateKey privKey;
			 PublicKey pubKey;

			 try
			 {
				 KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

				 g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

				 KeyPair p = g.generateKeyPair();

				 privKey = p.getPrivate();
				 pubKey = p.getPublic();
			 }
			 catch (Exception e)
			 {
				 fail("error setting up keys - " + e.ToString());
				 return;
			 }

			//
			// extensions
			//

			//
			// create the certificate - version 1
			//

			ContentSigner sigGen = (new JcaContentSignerBuilder("SM3withSM2")).setProvider(BC).build(privKey);
			JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(new X500Name("CN=Test"), BigInteger.valueOf(1), new DateTime(System.currentTimeMillis() - 50000), new DateTime(System.currentTimeMillis() + 50000), new X500Name("CN=Test"), pubKey);

			certGen.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

			X509Certificate cert = (new JcaX509CertificateConverter()).setProvider(BC).getCertificate(certGen.build(sigGen));

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).build("SM3withSM2", privKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

		   // tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SM3, new byte[32], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(cert));

			AttributeTable table = tsToken.getSignedAttributes();

			assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate));
		}

		private void resolutionTest(PrivateKey privateKey, X509Certificate cert, Store certs, int resolution, string timeString)
		{
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			tsTokenGen.setResolution(resolution);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new DateTime(9999L));

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");

			dateF.setTimeZone(new SimpleTimeZone(0, "Z"));

			assertEquals(timeString, tsToken.getTimeStampInfo().toASN1Structure().getGenTime().getTimeString());

			// test zero truncation
			tsResp = tsRespGen.generate(request, new BigInteger("23"), new DateTime(9000L));
			tsToken = tsResp.getTimeStampToken();

			assertEquals("19700101000009Z", tsToken.getTimeStampInfo().toASN1Structure().getGenTime().getTimeString());

			if (resolution > TimeStampTokenGenerator.R_MICROSECONDS)
			{
				tsResp = tsRespGen.generate(request, new BigInteger("23"), new DateTime(9990L));
				tsToken = tsResp.getTimeStampToken();

				assertEquals("19700101000009.99Z", tsToken.getTimeStampInfo().toASN1Structure().getGenTime().getTimeString());
			}
			if (resolution > TimeStampTokenGenerator.R_TENTHS_OF_SECONDS)
			{
				tsResp = tsRespGen.generate(request, new BigInteger("23"), new DateTime(9900L));
				tsToken = tsResp.getTimeStampToken();

				assertEquals("19700101000009.9Z", tsToken.getTimeStampInfo().toASN1Structure().getGenTime().getTimeString());
			}
		}

		private void basicSha256Test(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).build("SHA256withRSA", privateKey, cert), new SHA256DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA256, new byte[32], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			assertEquals(PKIStatus.GRANTED, tsResp.getStatus());

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(cert));

			AttributeTable table = tsToken.getSignedAttributes();

			assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificateV2));

			DigestCalculator digCalc = new SHA256DigestCalculator();

			OutputStream dOut = digCalc.getOutputStream();

			dOut.write(cert.getEncoded());

			dOut.close();

			byte[] certHash = digCalc.getDigest();

			SigningCertificateV2 sigCertV2 = SigningCertificateV2.getInstance(table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificateV2).getAttributeValues()[0]);

			assertTrue(Arrays.areEqual(certHash, sigCertV2.getCerts()[0].getCertHash()));
		}

		private void overrideAttrsTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSimpleSignerInfoGeneratorBuilder signerInfoGenBuilder = (new JcaSimpleSignerInfoGeneratorBuilder()).setProvider("BC");

			IssuerSerial issuerSerial = new IssuerSerial(new GeneralNames(new GeneralName((new X509CertificateHolder(cert.getEncoded())).getIssuer())), cert.getSerialNumber());

			DigestCalculator digCalc = new SHA1DigestCalculator();

			OutputStream dOut = digCalc.getOutputStream();

			dOut.write(cert.getEncoded());

			dOut.close();

			byte[] certHash = digCalc.getDigest();

			digCalc = new SHA256DigestCalculator();

			dOut = digCalc.getOutputStream();

			dOut.write(cert.getEncoded());

			dOut.close();

			byte[] certHash256 = digCalc.getDigest();

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ess.ESSCertID essCertid = new org.bouncycastle.asn1.ess.ESSCertID(certHash, issuerSerial);
			ESSCertID essCertid = new ESSCertID(certHash, issuerSerial);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ess.ESSCertIDv2 essCertidV2 = new org.bouncycastle.asn1.ess.ESSCertIDv2(certHash256, issuerSerial);
			ESSCertIDv2 essCertidV2 = new ESSCertIDv2(certHash256, issuerSerial);

			signerInfoGenBuilder.setSignedAttributeGenerator(new CMSAttributeTableGeneratorAnonymousInnerClass(this, essCertid, essCertidV2));

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(signerInfoGenBuilder.build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(cert));

			AttributeTable table = tsToken.getSignedAttributes();

			assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate));
			assertNotNull("no signingCertificateV2 attribute found", table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificateV2));

			SigningCertificate sigCert = SigningCertificate.getInstance(table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate).getAttributeValues()[0]);

			assertEquals((new X509CertificateHolder(cert.getEncoded())).getIssuer(), sigCert.getCerts()[0].getIssuerSerial().getIssuer().getNames()[0].getName());
			assertEquals(cert.getSerialNumber(), sigCert.getCerts()[0].getIssuerSerial().getSerial().getValue());
			assertTrue(Arrays.areEqual(certHash, sigCert.getCerts()[0].getCertHash()));

			SigningCertificateV2 sigCertV2 = SigningCertificateV2.getInstance(table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificateV2).getAttributeValues()[0]);

			assertEquals((new X509CertificateHolder(cert.getEncoded())).getIssuer(), sigCertV2.getCerts()[0].getIssuerSerial().getIssuer().getNames()[0].getName());
			assertEquals(cert.getSerialNumber(), sigCertV2.getCerts()[0].getIssuerSerial().getSerial().getValue());
			assertTrue(Arrays.areEqual(certHash256, sigCertV2.getCerts()[0].getCertHash()));
		}

		public class CMSAttributeTableGeneratorAnonymousInnerClass : CMSAttributeTableGenerator
		{
			private readonly NewTSPTest outerInstance;

			private ESSCertID essCertid;
			private ESSCertIDv2 essCertidV2;

			public CMSAttributeTableGeneratorAnonymousInnerClass(NewTSPTest outerInstance, ESSCertID essCertid, ESSCertIDv2 essCertidV2)
			{
				this.outerInstance = outerInstance;
				this.essCertid = essCertid;
				this.essCertidV2 = essCertidV2;
			}

			public AttributeTable getAttributes(Map parameters)
			{
				CMSAttributeTableGenerator attrGen = new DefaultSignedAttributeTableGenerator();

				AttributeTable table = attrGen.getAttributes(parameters);
				table = table.add(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate, new SigningCertificate(essCertid));
				table = table.add(PKCSObjectIdentifiers_Fields.id_aa_signingCertificateV2, new SigningCertificateV2(new ESSCertIDv2[]{essCertidV2}));

				return table;
			}
		}

		private void basicTestWithTSA(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);
			tsTokenGen.setTSA(new GeneralName(new X500Name("CN=Test")));

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(cert));

			AttributeTable table = tsToken.getSignedAttributes();

			assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate));
		}

		private void additionalExtensionTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);
			tsTokenGen.setTSA(new GeneralName(new X500Name("CN=Test")));

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			ExtensionsGenerator extGen = new ExtensionsGenerator();

			extGen.addExtension(Extension.auditIdentity, false, new DERUTF8String("Test"));

			TimeStampResponse tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), DateTime.Now, "Okay", extGen.generate());

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(cert));

			AttributeTable table = tsToken.getSignedAttributes();

			assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate));

			Extensions ext = tsToken.getTimeStampInfo().getExtensions();

			assertEquals(1, ext.getExtensionOIDs().Length);
			assertEquals(new Extension(Extension.auditIdentity, false, (new DERUTF8String("Test")).getEncoded()), ext.getExtension(Extension.auditIdentity));
		}

		private void responseValidationTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build());

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build((new JcaContentSignerBuilder("MD5withRSA")).setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(cert));

			//
			// check validation
			//
			tsResp.validate(request);

			try
			{
				request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(101));

				tsResp.validate(request);

				fail("response validation failed on invalid nonce.");
			}
			catch (TSPValidationException)
			{
				// ignore
			}

			try
			{
				request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[22], BigInteger.valueOf(100));

				tsResp.validate(request);

				fail("response validation failed on wrong digest.");
			}
			catch (TSPValidationException)
			{
				// ignore
			}

			try
			{
				request = reqGen.generate(TSPAlgorithms_Fields.MD5, new byte[20], BigInteger.valueOf(100));

				tsResp.validate(request);

				fail("response validation failed on wrong digest.");
			}
			catch (TSPValidationException)
			{
				// ignore
			}
		}

		private void incorrectHashTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build());

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build((new JcaContentSignerBuilder("SHA1withRSA")).setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[16]);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			if (tsToken != null)
			{
				fail("incorrectHash - token not null.");
			}

			PKIFailureInfo failInfo = tsResp.getFailInfo();

			if (failInfo == null)
			{
				fail("incorrectHash - failInfo set to null.");
			}

			if (failInfo.intValue() != PKIFailureInfo.badDataFormat)
			{
				fail("incorrectHash - wrong failure info returned.");
			}
		}

		private void badAlgorithmTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSimpleSignerInfoGeneratorBuilder infoGeneratorBuilder = (new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC);

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(new ASN1ObjectIdentifier("1.2.3.4.5"), new byte[20]);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			if (tsToken != null)
			{
				fail("badAlgorithm - token not null.");
			}

			PKIFailureInfo failInfo = tsResp.getFailInfo();

			if (failInfo == null)
			{
				fail("badAlgorithm - failInfo set to null.");
			}

			if (failInfo.intValue() != PKIFailureInfo.badAlg)
			{
				fail("badAlgorithm - wrong failure info returned.");
			}
		}

		private void timeNotAvailableTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build());

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build((new JcaContentSignerBuilder("SHA1withRSA")).setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(new ASN1ObjectIdentifier("1.2.3.4.5"), new byte[20]);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp;

			try
			{
				tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), null);
			}
			catch (TSPException e)
			{
				tsResp = tsRespGen.generateRejectedResponse(e);
			}

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			if (tsToken != null)
			{
				fail("timeNotAvailable - token not null.");
			}

			PKIFailureInfo failInfo = tsResp.getFailInfo();

			if (failInfo == null)
			{
				fail("timeNotAvailable - failInfo set to null.");
			}

			if (failInfo.intValue() != PKIFailureInfo.timeNotAvailable)
			{
				fail("timeNotAvailable - wrong failure info returned.");
			}
		}

		private void badPolicyTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build());

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build((new JcaContentSignerBuilder("SHA1withRSA")).setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

			reqGen.setReqPolicy(new ASN1ObjectIdentifier("1.1"));

			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20]);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED, new HashSet());

			TimeStampResponse tsResp;

			try
			{
				tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), DateTime.Now);
			}
			catch (TSPException e)
			{
				tsResp = tsRespGen.generateRejectedResponse(e);
			}

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			if (tsToken != null)
			{
				fail("badPolicy - token not null.");
			}

			PKIFailureInfo failInfo = tsResp.getFailInfo();

			if (failInfo == null)
			{
				fail("badPolicy - failInfo set to null.");
			}

			if (failInfo.intValue() != PKIFailureInfo.unacceptedPolicy)
			{
				fail("badPolicy - wrong failure info returned.");
			}
		}

		private void certReqTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build());

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build((new JcaContentSignerBuilder("MD5withRSA")).setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

			//
			// request with certReq false
			//
			reqGen.setCertReq(false);

			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			assertNull(tsToken.getTimeStampInfo().getGenTimeAccuracy()); // check for abscence of accuracy

			assertEquals("1.2", tsToken.getTimeStampInfo().getPolicy().getId());

			try
			{
				tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(cert));
			}
			catch (TSPValidationException)
			{
				fail("certReq(false) verification of token failed.");
			}

			Store respCerts = tsToken.getCertificates();

			Collection certsColl = respCerts.getMatches(null);

			if (!certsColl.isEmpty())
			{
				fail("certReq(false) found certificates in response.");
			}
		}


		private void tokenEncodingTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build());

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build((new JcaContentSignerBuilder("SHA1withRSA")).setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3.4.5.6"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));
			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);
			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampResponse tsResponse = new TimeStampResponse(tsResp.getEncoded());

			if (!Arrays.areEqual(tsResponse.getEncoded(), tsResp.getEncoded()) || !Arrays.areEqual(tsResponse.getTimeStampToken().getEncoded(), tsResp.getTimeStampToken().getEncoded()))
			{
				fail();
			}
		}

		private void testAccuracyZeroCerts(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build());

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build((new JcaContentSignerBuilder("MD5withRSA")).setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			tsTokenGen.setAccuracySeconds(1);
			tsTokenGen.setAccuracyMillis(2);
			tsTokenGen.setAccuracyMicros(3);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(cert));

			//
			// check validation
			//
			tsResp.validate(request);

			//
			// check tstInfo
			//
			TimeStampTokenInfo tstInfo = tsToken.getTimeStampInfo();

			//
			// check accuracy
			//
			GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

			assertEquals(1, accuracy.getSeconds());
			assertEquals(2, accuracy.getMillis());
			assertEquals(3, accuracy.getMicros());

			assertEquals(new BigInteger("23"), tstInfo.getSerialNumber());

			assertEquals("1.2", tstInfo.getPolicy().getId());

			//
			// test certReq
			//
			Store store = tsToken.getCertificates();

			Collection certificates = store.getMatches(null);

			assertEquals(0, certificates.size());
		}

		private void testAccuracyWithCertsAndOrdering(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build());

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build((new JcaContentSignerBuilder("MD5withRSA")).setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3"));

			tsTokenGen.addCertificates(certs);

			tsTokenGen.setAccuracySeconds(3);
			tsTokenGen.setAccuracyMillis(1);
			tsTokenGen.setAccuracyMicros(2);

			tsTokenGen.setOrdering(true);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

			reqGen.setCertReq(true);

			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			assertTrue(request.getCertReq());

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp;

			try
			{
				tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), DateTime.Now);
			}
			catch (TSPException e)
			{
				tsResp = tsRespGen.generateRejectedResponse(e);
			}

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(cert));

			//
			// check validation
			//
			tsResp.validate(request);

			//
			// check tstInfo
			//
			TimeStampTokenInfo tstInfo = tsToken.getTimeStampInfo();

			//
			// check accuracy
			//
			GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

			assertEquals(3, accuracy.getSeconds());
			assertEquals(1, accuracy.getMillis());
			assertEquals(2, accuracy.getMicros());

			assertEquals(new BigInteger("23"), tstInfo.getSerialNumber());

			assertEquals("1.2.3", tstInfo.getPolicy().getId());

			assertEquals(true, tstInfo.isOrdered());

			assertEquals(tstInfo.getNonce(), BigInteger.valueOf(100));

			//
			// test certReq
			//
			Store store = tsToken.getCertificates();

			Collection certificates = store.getMatches(null);

			assertEquals(2, certificates.size());
		}

		private void testNoNonse(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build());

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build((new JcaContentSignerBuilder("MD5withRSA")).setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20]);

			Set algorithms = new HashSet();

			algorithms.add(TSPAlgorithms_Fields.SHA1);

			request.validate(algorithms, new HashSet(), new HashSet());

			assertFalse(request.getCertReq());

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("24"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(cert));

			//
			// check validation
			//
			tsResp.validate(request);

			//
			// check tstInfo
			//
			TimeStampTokenInfo tstInfo = tsToken.getTimeStampInfo();

			//
			// check accuracy
			//
			GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

			assertNull(accuracy);

			assertEquals(new BigInteger("24"), tstInfo.getSerialNumber());

			assertEquals("1.2.3", tstInfo.getPolicy().getId());

			assertEquals(false, tstInfo.isOrdered());

			assertNull(tstInfo.getNonce());

			//
			// test certReq
			//
			Store store = tsToken.getCertificates();

			Collection certificates = store.getMatches(null);

			assertEquals(0, certificates.size());
		}

		private void extensionTest(PrivateKey privateKey, X509Certificate cert, Store certs)
		{
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

			// test case only!!!
			reqGen.setReqPolicy(Extension.noRevAvail);
			// test case only!!!
			reqGen.addExtension(Extension.biometricInfo, true, new DEROctetString(new byte[20]));

			TimeStampRequest request = reqGen.generate(TSPAlgorithms_Fields.SHA1, new byte[20], BigInteger.valueOf(100));

			try
			{
				request.validate(new HashSet(), new HashSet(), new HashSet());
				fail("no exception");
			}
			catch (Exception e)
			{
				assertEquals(e.Message, "request contains unknown algorithm");
			}

			Set algorithms = new HashSet();

			algorithms.add(TSPAlgorithms_Fields.SHA1);

			try
			{
				request.validate(algorithms, new HashSet(), new HashSet());
				fail("no exception");
			}
			catch (Exception e)
			{
				assertEquals(e.Message, "request contains unknown policy");
			}

			Set policies = new HashSet();

			policies.add(Extension.noRevAvail);

			try
			{
				request.validate(algorithms, policies, new HashSet());
				fail("no exception");
			}
			catch (Exception e)
			{
				assertEquals(e.Message, "request contains unknown extension");
			}

			Set extensions = new HashSet();

			extensions.add(Extension.biometricInfo);

			// should validate with full set
			request.validate(algorithms, policies, extensions);

			// should validate with null policy
			request.validate(algorithms, null, extensions);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			TimeStampToken tsToken = tsResp.getTimeStampToken();

			tsToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(cert));

			AttributeTable table = tsToken.getSignedAttributes();

			assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate));
		}
	}

}