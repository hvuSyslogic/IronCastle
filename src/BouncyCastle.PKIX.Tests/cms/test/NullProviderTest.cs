using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.cms.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using JcaX509CertSelectorConverter = org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
	using JceCMSContentEncryptorBuilder = org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
	using JceKeyTransEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
	using JceKeyTransRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using JcaContentSignerBuilder = org.bouncycastle.@operator.jcajce.JcaContentSignerBuilder;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;
	using CollectionStore = org.bouncycastle.util.CollectionStore;
	using Store = org.bouncycastle.util.Store;
	using X509V3CertificateGenerator = org.bouncycastle.x509.X509V3CertificateGenerator;

	public class NullProviderTest : TestCase
	{
		internal static KeyPair keyPair;
		internal static X509Certificate keyCert;
		private const string TEST_MESSAGE = "Hello World!";

		private JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

		static NullProviderTest()
		{
			try
			{
				keyPair = generateKeyPair();
				string origDN = "O=Bouncy Castle, C=AU";
				keyCert = makeCertificate(keyPair, origDN, keyPair, origDN);
			}
			catch (Exception e)
			{
				throw new RuntimeException(e);
			}
		}

		public virtual void testSHA1WithRSAEncapsulated()
		{
			List certList = new ArrayList();
			CMSTypedData msg = new CMSProcessableByteArray(TEST_MESSAGE.GetBytes());

			certList.add(new X509CertificateHolder(keyCert.getEncoded()));

			DigestCalculatorProvider digCalcProv = (new JcaDigestCalculatorProviderBuilder()).build();

			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

			gen.addSignerInfoGenerator((new JcaSignerInfoGeneratorBuilder(digCalcProv)).build((new JcaContentSignerBuilder("SHA1withRSA")).build(keyPair.getPrivate()), keyCert));

			gen.addCertificates(new CollectionStore(certList));

			CMSSignedData s = gen.generate(msg, true);

			ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
			ASN1InputStream aIn = new ASN1InputStream(bIn);

			s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

			Store certsAndCrls = s.getCertificates();

			SignerInformationStore signers = s.getSignerInfos();
			Collection c = signers.getSigners();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();
				Collection certCollection = certsAndCrls.getMatches(signer.getSID());
				Iterator certIt = certCollection.iterator();
				X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

				assertEquals(true, signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).build(cert)));
			}
		}

		public virtual void testSHA1WithRSAStream()
		{
			List certList = new ArrayList();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			certList.add(new X509CertificateHolder(keyCert.getEncoded()));

			DigestCalculatorProvider digCalcProv = (new JcaDigestCalculatorProviderBuilder()).build();

			CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

			gen.addSignerInfoGenerator((new JcaSignerInfoGeneratorBuilder(digCalcProv)).build((new JcaContentSignerBuilder("SHA1withRSA")).build(keyPair.getPrivate()), keyCert));

			gen.addCertificates(new CollectionStore(certList));

			OutputStream sigOut = gen.open(bOut);

			sigOut.write(TEST_MESSAGE.GetBytes());

			sigOut.close();

			CMSSignedDataParser sp = new CMSSignedDataParser(digCalcProv, new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.GetBytes())), bOut.toByteArray());

			sp.getSignedContent().drain();

			//
			// compute expected content digest
			//
			MessageDigest md = MessageDigest.getInstance("SHA1");

			byte[] contentDigest = md.digest(TEST_MESSAGE.GetBytes());
			Store certStore = sp.getCertificates();
			SignerInformationStore signers = sp.getSignerInfos();

			Collection c = signers.getSigners();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();
				Collection certCollection = certStore.getMatches(signer.getSID());

				Iterator certIt = certCollection.iterator();
				X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

				assertEquals(true, signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).build(cert)));

				if (contentDigest != null)
				{
					assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
				}
			}
		}

		public virtual void testKeyTransDES()
		{
			testKeyTrans(CMSEnvelopedDataGenerator.DES_EDE3_CBC);
		}

		public virtual void testKeyTransAES128()
		{
			testKeyTrans(CMSEnvelopedDataGenerator.AES128_CBC);
		}

		public virtual void testKeyTransAES192()
		{
			testKeyTrans(CMSEnvelopedDataGenerator.AES192_CBC);
		}

		public virtual void testKeyTransAES256()
		{
			testKeyTrans(CMSEnvelopedDataGenerator.AES256_CBC);
		}

		private void testKeyTrans(string algorithm)
		{
			byte[] data = "WallaWallaWashington".GetBytes();

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(keyCert));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(algorithm))).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals(ed.getEncryptionAlgOID(), algorithm);

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(keyPair.getPrivate()));

				assertEquals(true, Arrays.Equals(data, recData));
			}
		}

		private static KeyPair generateKeyPair()
		{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SunRsaSign");

			kpg.initialize(512, new SecureRandom());

			return kpg.generateKeyPair();
		}

		private static X509Certificate makeCertificate(KeyPair subKP, string _subDN, KeyPair issKP, string _issDN)
		{

			PublicKey subPub = subKP.getPublic();
			PrivateKey issPriv = issKP.getPrivate();
			PublicKey issPub = issKP.getPublic();

			X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();

			v3CertGen.reset();
			v3CertGen.setSerialNumber(BigInteger.valueOf(1));
			v3CertGen.setIssuerDN(new X509Name(_issDN));
			v3CertGen.setNotBefore(new DateTime(System.currentTimeMillis()));
			v3CertGen.setNotAfter(new DateTime(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)));
			v3CertGen.setSubjectDN(new X509Name(_subDN));
			v3CertGen.setPublicKey(subPub);

			v3CertGen.setSignatureAlgorithm("SHA1WithRSA");

			X509Certificate _cert = v3CertGen.generate(issPriv, "SunRsaSign");

			_cert.checkValidity(DateTime.Now);
			_cert.verify(issPub);

			return _cert;
		}

		public static Test suite()
		{
			return new TestSuite(typeof(NullProviderTest));
		}
	}

}