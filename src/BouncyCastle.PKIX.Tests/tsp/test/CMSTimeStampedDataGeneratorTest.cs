using org.bouncycastle.asn1.nist;
using org.bouncycastle.tsp;

using System;

namespace org.bouncycastle.tsp.test
{

	using TestCase = junit.framework.TestCase;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using JcaCertStore = org.bouncycastle.cert.jcajce.JcaCertStore;
	using JcaSimpleSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using BcDigestCalculatorProvider = org.bouncycastle.@operator.bc.BcDigestCalculatorProvider;
	using CMSTimeStampedData = org.bouncycastle.tsp.cms.CMSTimeStampedData;
	using CMSTimeStampedDataGenerator = org.bouncycastle.tsp.cms.CMSTimeStampedDataGenerator;
	using CMSTimeStampedDataParser = org.bouncycastle.tsp.cms.CMSTimeStampedDataParser;
	using Arrays = org.bouncycastle.util.Arrays;
	using Store = org.bouncycastle.util.Store;
	using Streams = org.bouncycastle.util.io.Streams;

	public class CMSTimeStampedDataGeneratorTest : TestCase
	{

		internal BouncyCastleProvider bouncyCastleProvider;
		internal CMSTimeStampedDataGenerator cmsTimeStampedDataGenerator = null;
		internal string fileInput = "FileDaFirmare.data";
		internal byte[] baseData;

		public virtual void setUp()
		{
			bouncyCastleProvider = new BouncyCastleProvider();
			if (Security.getProvider(bouncyCastleProvider.getName()) == null)
			{
				Security.addProvider(bouncyCastleProvider);
			}

			cmsTimeStampedDataGenerator = new CMSTimeStampedDataGenerator();
			ByteArrayOutputStream origStream = new ByteArrayOutputStream();
			InputStream @in = this.GetType().getResourceAsStream(fileInput);
			int ch;

			while ((ch = @in.read()) >= 0)
			{
				origStream.write(ch);
			}

			origStream.close();

			this.baseData = origStream.toByteArray();

		}

		public virtual void tearDown()
		{
			cmsTimeStampedDataGenerator = null;
			Security.removeProvider(bouncyCastleProvider.getName());
		}

		public virtual void testGenerate()
		{
			BcDigestCalculatorProvider calculatorProvider = new BcDigestCalculatorProvider();
			ASN1ObjectIdentifier algOID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"); // SHA-256
			DigestCalculator hashCalculator = calculatorProvider.get(new AlgorithmIdentifier(algOID));

			cmsTimeStampedDataGenerator.initialiseMessageImprintDigestCalculator(hashCalculator);

			hashCalculator.getOutputStream().write(baseData);
			hashCalculator.getOutputStream().close();

			TimeStampToken timeStampToken = createTimeStampToken(hashCalculator.getDigest(), NISTObjectIdentifiers_Fields.id_sha256);
			CMSTimeStampedData cmsTimeStampedData = cmsTimeStampedDataGenerator.generate(timeStampToken, baseData);

			for (int i = 0; i < 3; i++)
			{
				byte[] newRequestData = cmsTimeStampedData.calculateNextHash(hashCalculator);
				TimeStampToken newTimeStampToken = createTimeStampToken(newRequestData, NISTObjectIdentifiers_Fields.id_sha256);
				cmsTimeStampedData = cmsTimeStampedData.addTimeStamp(newTimeStampToken);
			}
			byte[] timeStampedData = cmsTimeStampedData.getEncoded();

			// verify
			DigestCalculatorProvider newCalculatorProvider = new BcDigestCalculatorProvider();
			DigestCalculator imprintCalculator = cmsTimeStampedData.getMessageImprintDigestCalculator(newCalculatorProvider);
			CMSTimeStampedData newCMSTimeStampedData = new CMSTimeStampedData(timeStampedData);
			byte[] newContent = newCMSTimeStampedData.getContent();
			assertEquals("Content expected and verified are different", true, Arrays.areEqual(newContent, baseData));

			imprintCalculator.getOutputStream().write(newContent);

			byte[] digest = imprintCalculator.getDigest();

			TimeStampToken[] tokens = cmsTimeStampedData.getTimeStampTokens();
			assertEquals("TimeStampToken expected and verified are different", 4, tokens.Length);
			for (int i = 0; i < tokens.Length; i++)
			{
				cmsTimeStampedData.validate(newCalculatorProvider, digest, tokens[i]);
			}
		}

		public virtual void testGenerateWithMetadata()
		{
			cmsTimeStampedDataGenerator.setMetaData(true, fileInput, "TXT");

			BcDigestCalculatorProvider calculatorProvider = new BcDigestCalculatorProvider();
			ASN1ObjectIdentifier algOID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"); // SHA-256
			DigestCalculator hashCalculator = calculatorProvider.get(new AlgorithmIdentifier(algOID));

			cmsTimeStampedDataGenerator.initialiseMessageImprintDigestCalculator(hashCalculator);

			hashCalculator.getOutputStream().write(baseData);
			hashCalculator.getOutputStream().close();

			TimeStampToken timeStampToken = createTimeStampToken(hashCalculator.getDigest(), NISTObjectIdentifiers_Fields.id_sha256);
			CMSTimeStampedData cmsTimeStampedData = cmsTimeStampedDataGenerator.generate(timeStampToken, baseData);

			for (int i = 0; i <= 3; i++)
			{
				byte[] newRequestData = cmsTimeStampedData.calculateNextHash(hashCalculator);
				TimeStampToken newTimeStampToken = createTimeStampToken(newRequestData, NISTObjectIdentifiers_Fields.id_sha256);
				cmsTimeStampedData = cmsTimeStampedData.addTimeStamp(newTimeStampToken);
			}
			byte[] timeStampedData = cmsTimeStampedData.getEncoded();

			metadataCheck(timeStampedData);
			metadataParserCheck(timeStampedData);
		}

		public virtual void testGenerateWithMetadataAndDifferentAlgorithmIdentifier()
		{
			cmsTimeStampedDataGenerator.setMetaData(true, fileInput, "TXT");

			BcDigestCalculatorProvider calculatorProvider = new BcDigestCalculatorProvider();

			ASN1ObjectIdentifier algIdentifier = NISTObjectIdentifiers_Fields.id_sha224;

			DigestCalculator hashCalculator = calculatorProvider.get(new AlgorithmIdentifier(algIdentifier));
			cmsTimeStampedDataGenerator.initialiseMessageImprintDigestCalculator(hashCalculator);
			hashCalculator.getOutputStream().write(baseData);
			hashCalculator.getOutputStream().close();

			byte[] requestData = hashCalculator.getDigest();
			TimeStampToken timeStampToken = createTimeStampToken(requestData, algIdentifier);

			CMSTimeStampedData cmsTimeStampedData = cmsTimeStampedDataGenerator.generate(timeStampToken, baseData);

			for (int i = 0; i <= 3; i++)
			{
				switch (i)
				{
				case 0:
					algIdentifier = NISTObjectIdentifiers_Fields.id_sha224;
					break;
				case 1:
					algIdentifier = NISTObjectIdentifiers_Fields.id_sha256;
					break;
				case 2:
					algIdentifier = NISTObjectIdentifiers_Fields.id_sha384;
					break;
				case 3:
					algIdentifier = NISTObjectIdentifiers_Fields.id_sha512;
					break;
				}
				hashCalculator = calculatorProvider.get(new AlgorithmIdentifier(algIdentifier));
				byte[] newRequestData = cmsTimeStampedData.calculateNextHash(hashCalculator);
				TimeStampToken newTimeStampToken = createTimeStampToken(newRequestData, algIdentifier);
				cmsTimeStampedData = cmsTimeStampedData.addTimeStamp(newTimeStampToken);
			}
			byte[] timeStampedData = cmsTimeStampedData.getEncoded();

			metadataCheck(timeStampedData);
			metadataParserCheck(timeStampedData);

		}


		private void metadataCheck(byte[] timeStampedData)
		{
			CMSTimeStampedData cmsTspData = new CMSTimeStampedData(timeStampedData);
			DigestCalculatorProvider newCalculatorProvider = new BcDigestCalculatorProvider();
			DigestCalculator imprintCalculator = cmsTspData.getMessageImprintDigestCalculator(newCalculatorProvider);

			byte[] newContent = cmsTspData.getContent();
			assertEquals("Content expected and verified are different", true, Arrays.areEqual(newContent, baseData));

			imprintCalculator.getOutputStream().write(newContent);

			assertEquals(fileInput, cmsTspData.getFileName());
			assertEquals("TXT", cmsTspData.getMediaType());

			byte[] digest = imprintCalculator.getDigest();

			TimeStampToken[] tokens = cmsTspData.getTimeStampTokens();
			assertEquals("TimeStampToken expected and verified are different", 5, tokens.Length);
			for (int i = 0; i < tokens.Length; i++)
			{
				cmsTspData.validate(newCalculatorProvider, digest, tokens[i]);
			}
		}

		private void metadataParserCheck(byte[] timeStampedData)
		{
			CMSTimeStampedDataParser cmsTspData = new CMSTimeStampedDataParser(timeStampedData);
			DigestCalculatorProvider newCalculatorProvider = new BcDigestCalculatorProvider();

			InputStream input = cmsTspData.getContent();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			Streams.pipeAll(input, bOut);

			assertEquals("Content expected and verified are different", true, Arrays.areEqual(bOut.toByteArray(), baseData));

			DigestCalculator imprintCalculator = cmsTspData.getMessageImprintDigestCalculator(newCalculatorProvider);

			Streams.pipeAll(new ByteArrayInputStream(bOut.toByteArray()), imprintCalculator.getOutputStream());

			assertEquals(fileInput, cmsTspData.getFileName());
			assertEquals("TXT", cmsTspData.getMediaType());

			byte[] digest = imprintCalculator.getDigest();

			TimeStampToken[] tokens = cmsTspData.getTimeStampTokens();
			assertEquals("TimeStampToken expected and verified are different", 5, tokens.Length);
			for (int i = 0; i < tokens.Length; i++)
			{
				cmsTspData.validate(newCalculatorProvider, digest, tokens[i]);
			}
		}

		private TimeStampToken createTimeStampToken(byte[] hash, ASN1ObjectIdentifier hashAlg)
		{
			string algorithmName = null;
			if (hashAlg.Equals(NISTObjectIdentifiers_Fields.id_sha224))
			{
				algorithmName = "SHA224withRSA";
			}
			else if (hashAlg.Equals(NISTObjectIdentifiers_Fields.id_sha256))
			{
				algorithmName = "SHA256withRSA";
			}
			else if (hashAlg.Equals(NISTObjectIdentifiers_Fields.id_sha384))
			{
				algorithmName = "SHA384withRSA";
			}
			else if (hashAlg.Equals(NISTObjectIdentifiers_Fields.id_sha512))
			{
				algorithmName = "SHA512withRSA";
			}

			string signDN = "O=Bouncy Castle, C=AU";
			KeyPair signKP = TSPTestUtil.makeKeyPair();
			X509Certificate signCert = TSPTestUtil.makeCACertificate(signKP, signDN, signKP, signDN);

			string origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
			KeyPair origKP = TSPTestUtil.makeKeyPair();
			X509Certificate cert = TSPTestUtil.makeCertificate(origKP, origDN, signKP, signDN);

			PrivateKey privateKey = origKP.getPrivate();

			List certList = new ArrayList();
			certList.add(cert);
			certList.add(signCert);

			Store certs = new JcaCertStore(certList);


			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider("BC").build(algorithmName, privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

			tsTokenGen.addCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.generate(hashAlg, hash);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms_Fields.ALLOWED);

			TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), DateTime.Now);

			tsResp = new TimeStampResponse(tsResp.getEncoded());

			return tsResp.getTimeStampToken();
		}
	}

}