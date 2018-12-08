using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERUTF8String = org.bouncycastle.asn1.DERUTF8String;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSAttributes = org.bouncycastle.asn1.cms.CMSAttributes;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using JcaSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
	using JcaX509CertSelectorConverter = org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
	using JceKeyTransEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;
	using Store = org.bouncycastle.util.Store;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using Streams = org.bouncycastle.util.io.Streams;

	public class Rfc4134Test : TestCase
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;
		private const string TEST_DATA_HOME = "bc.test.data.home";

		private static byte[] exContent = getRfc4134Data("ExContent.bin");
		private static byte[] sha1 = Hex.decode("406aec085279ba6e16022d9e0629c0229687dd48");

		private static readonly JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();
		private static readonly DigestCalculatorProvider digCalcProv;

		static Rfc4134Test()
		{
			try
			{
				digCalcProv = (new JcaDigestCalculatorProviderBuilder()).build();
			}
			catch (OperatorCreationException)
			{
				throw new IllegalStateException("can't create default provider!!!");
			}
		}

		public Rfc4134Test(string name) : base(name)
		{
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			junit.textui.TestRunner.run(typeof(Rfc4134Test));
		}

		public static Test suite()
		{
			return new CMSTestSetup(new TestSuite(typeof(Rfc4134Test)));
		}

		public virtual void test4_1()
		{
			byte[] data = getRfc4134Data("4.1.bin");
			CMSSignedData signedData = new CMSSignedData(data);

			verifySignatures(signedData);

			CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

			verifySignatures(parser);
		}

		public virtual void test4_2()
		{
			byte[] data = getRfc4134Data("4.2.bin");
			CMSSignedData signedData = new CMSSignedData(data);

			verifySignatures(signedData);

			CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

			verifySignatures(parser);
		}

		public virtual void testRfc4_3()
		{
			byte[] data = getRfc4134Data("4.3.bin");
			CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(exContent), data);

			verifySignatures(signedData, sha1);

			CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, new CMSTypedStream(new ByteArrayInputStream(exContent)), data);

			verifySignatures(parser);
		}

		public virtual void test4_4()
		{
			byte[] data = getRfc4134Data("4.4.bin");
			byte[] counterSigCert = getRfc4134Data("AliceRSASignByCarl.cer");
			CMSSignedData signedData = new CMSSignedData(data);

			verifySignatures(signedData, sha1);

			verifySignerInfo4_4(getFirstSignerInfo(signedData.getSignerInfos()), counterSigCert);

			CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

			verifySignatures(parser);

			verifySignerInfo4_4(getFirstSignerInfo(parser.getSignerInfos()), counterSigCert);
		}

		public virtual void test4_5()
		{
			byte[] data = getRfc4134Data("4.5.bin");
			CMSSignedData signedData = new CMSSignedData(data);

			verifySignatures(signedData);

			CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

			verifySignatures(parser);
		}

		public virtual void test4_6()
		{
			byte[] data = getRfc4134Data("4.6.bin");
			CMSSignedData signedData = new CMSSignedData(data);

			verifySignatures(signedData);

			CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

			verifySignatures(parser);
		}

		public virtual void test4_7()
		{
			byte[] data = getRfc4134Data("4.7.bin");
			CMSSignedData signedData = new CMSSignedData(data);

			verifySignatures(signedData);

			CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

			verifySignatures(parser);
		}

		public virtual void test5_1()
		{
			byte[] data = getRfc4134Data("5.1.bin");
			CMSEnvelopedData envelopedData = new CMSEnvelopedData(data);

			verifyEnvelopedData(envelopedData, CMSEnvelopedDataGenerator.DES_EDE3_CBC);

			CMSEnvelopedDataParser envelopedParser = new CMSEnvelopedDataParser(data);

			verifyEnvelopedData(envelopedParser, CMSEnvelopedDataGenerator.DES_EDE3_CBC);
		}

		public virtual void test5_2()
		{
			byte[] data = getRfc4134Data("5.2.bin");
			CMSEnvelopedData envelopedData = new CMSEnvelopedData(data);

			verifyEnvelopedData(envelopedData, CMSEnvelopedDataGenerator.RC2_CBC);

			CMSEnvelopedDataParser envelopedParser = new CMSEnvelopedDataParser(data);

			verifyEnvelopedData(envelopedParser, CMSEnvelopedDataGenerator.RC2_CBC);
		}

		private void verifyEnvelopedData(CMSEnvelopedData envelopedData, string symAlgorithmOID)
		{
			byte[] privKeyData = getRfc4134Data("BobPrivRSAEncrypt.pri");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyData);
			KeyFactory keyFact = KeyFactory.getInstance("RSA", BC);
			PrivateKey privKey = keyFact.generatePrivate(keySpec);

			RecipientInformationStore recipients = envelopedData.getRecipientInfos();

			assertEquals(envelopedData.getEncryptionAlgOID(), symAlgorithmOID);

			Collection c = recipients.getRecipients();
			assertTrue(c.size() >= 1 && c.size() <= 2);

			Iterator it = c.iterator();
			verifyRecipient((RecipientInformation)it.next(), privKey);

			if (c.size() == 2)
			{
				RecipientInformation recInfo = (RecipientInformation)it.next();

				assertEquals(PKCSObjectIdentifiers_Fields.id_alg_CMSRC2wrap.getId(), recInfo.getKeyEncryptionAlgOID());
			}
		}

		private void verifyEnvelopedData(CMSEnvelopedDataParser envelopedParser, string symAlgorithmOID)
		{
			byte[] privKeyData = getRfc4134Data("BobPrivRSAEncrypt.pri");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyData);
			KeyFactory keyFact = KeyFactory.getInstance("RSA", BC);
			PrivateKey privKey = keyFact.generatePrivate(keySpec);

			RecipientInformationStore recipients = envelopedParser.getRecipientInfos();

			assertEquals(envelopedParser.getEncryptionAlgOID(), symAlgorithmOID);

			Collection c = recipients.getRecipients();
			assertTrue(c.size() >= 1 && c.size() <= 2);

			Iterator it = c.iterator();
			verifyRecipient((RecipientInformation)it.next(), privKey);

			if (c.size() == 2)
			{
				RecipientInformation recInfo = (RecipientInformation)it.next();

				assertEquals(PKCSObjectIdentifiers_Fields.id_alg_CMSRC2wrap.getId(), recInfo.getKeyEncryptionAlgOID());
			}
		}

		private void verifyRecipient(RecipientInformation recipient, PrivateKey privKey)
		{
			assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

			byte[] recData = recipient.getContent((new JceKeyTransEnvelopedRecipient(privKey)).setProvider(BC));

			assertEquals(true, Arrays.Equals(exContent, recData));
		}

		private void verifySignerInfo4_4(SignerInformation signerInfo, byte[] counterSigCert)
		{
			verifyCounterSignature(signerInfo, counterSigCert);

			verifyContentHint(signerInfo);
		}

		private SignerInformation getFirstSignerInfo(SignerInformationStore store)
		{
			return (SignerInformation)store.getSigners().iterator().next();
		}

		private void verifyCounterSignature(SignerInformation signInfo, byte[] certificate)
		{
			SignerInformation csi = (SignerInformation)signInfo.getCounterSignatures().getSigners().iterator().next();

			CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);
			X509Certificate cert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(certificate));

			assertTrue(csi.verify((new JcaSignerInfoVerifierBuilder(digCalcProv)).setProvider(BC).build(cert)));
		}

		private void verifyContentHint(SignerInformation signInfo)
		{
			AttributeTable attrTable = signInfo.getUnsignedAttributes();

			Attribute attr = attrTable.get(CMSAttributes_Fields.contentHint);

			assertEquals(1, attr.getAttrValues().size());

			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new DERUTF8String("Content Hints Description Buffer"));
			v.add(CMSObjectIdentifiers_Fields.data);

			assertTrue(attr.getAttrValues().getObjectAt(0).Equals(new DERSequence(v)));
		}

		private void verifySignatures(CMSSignedData s, byte[] contentDigest)
		{
			Store certStore = s.getCertificates();
			SignerInformationStore signers = s.getSignerInfos();

			Collection c = signers.getSigners();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();
				Collection certCollection = certStore.getMatches(signer.getSID());

				Iterator certIt = certCollection.iterator();
				X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

				verifySigner(signer, cert);

				if (contentDigest != null)
				{
					assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
				}
			}
		}

		private void verifySignatures(CMSSignedData s)
		{
			verifySignatures(s, null);
		}

		private void verifySignatures(CMSSignedDataParser sp)
		{
			CMSTypedStream sc = sp.getSignedContent();
			if (sc != null)
			{
				sc.drain();
			}

			Store certs = sp.getCertificates();
			SignerInformationStore signers = sp.getSignerInfos();

			Collection c = signers.getSigners();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();
				Collection certCollection = certs.getMatches(signer.getSID());

				Iterator certIt = certCollection.iterator();
				X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

				verifySigner(signer, cert);
			}
		}

		private void verifySigner(SignerInformation signer, X509CertificateHolder certHolder)
		{
			X509Certificate cert = (new JcaX509CertificateConverter()).setProvider("BC").getCertificate(certHolder);
			if (cert.getPublicKey() is DSAPublicKey)
			{
				DSAPublicKey key = (DSAPublicKey)cert.getPublicKey();

				if (key.getParams() == null)
				{
					assertEquals(true, signer.verify((new JcaSignerInfoVerifierBuilder(digCalcProv)).setProvider(BC).build(getInheritedKey(key))));
				}
				else
				{
					assertEquals(true, signer.verify((new JcaSignerInfoVerifierBuilder(digCalcProv)).setProvider(BC).build(cert)));
				}
			}
			else
			{
				assertEquals(true, signer.verify((new JcaSignerInfoVerifierBuilder(digCalcProv)).setProvider(BC).build(cert)));
			}
		}

		private PublicKey getInheritedKey(DSAPublicKey key)
		{
			CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

			X509Certificate cert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(getRfc4134Data("CarlDSSSelf.cer")));

			DSAParams dsaParams = ((DSAPublicKey)cert.getPublicKey()).getParams();

			DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(key.getY(), dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

			KeyFactory keyFactory = KeyFactory.getInstance("DSA", BC);

			return keyFactory.generatePublic(dsaPubKeySpec);
		}

		private static byte[] getRfc4134Data(string name)
		{
			string dataHome = System.getProperty(TEST_DATA_HOME);

			if (string.ReferenceEquals(dataHome, null))
			{
				throw new IllegalStateException(TEST_DATA_HOME + " property not set");
			}

			try
			{
				return Streams.readAll(new FileInputStream(dataHome + "/rfc4134/" + name));
			}
			catch (IOException e)
			{
				throw new RuntimeException(e.ToString());
			}
		}
	}

}