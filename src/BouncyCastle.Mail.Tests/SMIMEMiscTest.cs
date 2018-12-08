using System;

namespace org.bouncycastle.mail.smime.test
{


	using TestCase = junit.framework.TestCase;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using SMIMECapabilitiesAttribute = org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
	using SMIMECapability = org.bouncycastle.asn1.smime.SMIMECapability;
	using SMIMECapabilityVector = org.bouncycastle.asn1.smime.SMIMECapabilityVector;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaCertStore = org.bouncycastle.cert.jcajce.JcaCertStore;
	using CMSAlgorithm = org.bouncycastle.cms.CMSAlgorithm;
	using CMSException = org.bouncycastle.cms.CMSException;
	using RecipientInformation = org.bouncycastle.cms.RecipientInformation;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using JcaSimpleSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using JcaX509CertSelectorConverter = org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
	using JceCMSContentEncryptorBuilder = org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
	using JceKeyTransEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
	using JceKeyTransRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
	using ZlibCompressor = org.bouncycastle.cms.jcajce.ZlibCompressor;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using FileBackedMimeBodyPart = org.bouncycastle.mail.smime.util.FileBackedMimeBodyPart;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;
	using Store = org.bouncycastle.util.Store;

	public class SMIMEMiscTest : TestCase
	{
		internal static MimeBodyPart msg;

		internal static string signDN;
		internal static KeyPair signKP;
		internal static X509Certificate signCert;

		internal static string origDN;
		internal static KeyPair origKP;
		internal static X509Certificate origCert;

		internal static string reciDN;
		internal static KeyPair reciKP;
		internal static X509Certificate reciCert;

		private static readonly JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

		internal KeyPair dsaSignKP;
		internal X509Certificate dsaSignCert;

		internal KeyPair dsaOrigKP;
		internal X509Certificate dsaOrigCert;

		static SMIMEMiscTest()
		{
			try
			{
				if (Security.getProvider("BC") == null)
				{
					Security.addProvider(new BouncyCastleProvider());
				}

				msg = SMIMETestUtil.makeMimeBodyPart("Hello world!\n");

				signDN = "O=Bouncy Castle, C=AU";
				signKP = CMSTestUtil.makeKeyPair();
				signCert = CMSTestUtil.makeCertificate(signKP, signDN, signKP, signDN);

				origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
				origKP = CMSTestUtil.makeKeyPair();
				origCert = CMSTestUtil.makeCertificate(origKP, origDN, signKP, signDN);
			}
			catch (Exception e)
			{
				throw new RuntimeException("problem setting up signed test class: " + e);
			}
		}

		/*
		 *
		 *  INFRASTRUCTURE
		 *
		 */

		public SMIMEMiscTest(string name) : base(name)
		{
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			junit.textui.TestRunner.run(typeof(SMIMEMiscTest));
		}

		public virtual void testSHA256WithRSAParserEncryptedWithAES()
		{
			List certList = new ArrayList();

			certList.add(origCert);
			certList.add(signCert);

			Store certs = new JcaCertStore(certList);

			SMIMEEnvelopedGenerator encGen = new SMIMEEnvelopedGenerator();

			encGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(origCert)).setProvider("BC"));

			MimeBodyPart mp = encGen.generate(msg, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider("BC").build());
			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider("BC").setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA256withRSA", origKP.getPrivate(), origCert));
			gen.addCertificates(certs);

			MimeMultipart smm = gen.generate(mp);
			File tmpFile = File.createTempFile("bcTest", ".mime");

			MimeMessage msg = createMimeMessage(tmpFile, smm);

			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider("BC").build(), (MimeMultipart)msg.getContent());

			certs = s.getCertificates();

			verifyMessageBytes(mp, s.getContent());

			verifySigners(certs, s.getSignerInfos());

			tmpFile.delete();
		}

		public virtual void testSHA256WithRSACompressed()
		{
			List certList = new ArrayList();

			certList.add(origCert);
			certList.add(signCert);

			Store certs = new JcaCertStore(certList);

			SMIMECompressedGenerator cGen = new SMIMECompressedGenerator();

			MimeBodyPart mp = cGen.generate(msg, new ZlibCompressor());

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider("BC").setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA256withRSA", origKP.getPrivate(), origCert));
			gen.addCertificates(certs);

			MimeMultipart smm = gen.generate(mp);
			File tmpFile = File.createTempFile("bcTest", ".mime");

			MimeMessage msg = createMimeMessage(tmpFile, smm);

			SMIMESigned s = new SMIMESigned((MimeMultipart)msg.getContent());

			certs = s.getCertificates();

			verifyMessageBytes(mp, s.getContent());

			verifySigners(certs, s.getSignerInfos());

			tmpFile.delete();
		}

		public virtual void testQuotePrintableSigPreservation()
		{
			MimeMessage msg = new MimeMessage((Session)null, this.GetType().getResourceAsStream("qp-soft-break.eml"));

			SMIMEEnvelopedGenerator encGen = new SMIMEEnvelopedGenerator();

			encGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(origCert)).setProvider("BC"));

			MimeBodyPart mp = encGen.generate(msg, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider("BC").build());

			SMIMEEnveloped env = new SMIMEEnveloped(mp);
			RecipientInformation ri = (RecipientInformation)env.getRecipientInfos().getRecipients().iterator().next();
			MimeBodyPart mm = SMIMEUtil.toMimeBodyPart(ri.getContentStream((new JceKeyTransEnvelopedRecipient(origKP.getPrivate())).setProvider("BC")));
			SMIMESigned s = new SMIMESigned((MimeMultipart)mm.getContent());
			Collection c = s.getSignerInfos().getSigners();
			Iterator it = c.iterator();
			Store certs = s.getCertificates();

			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();
				Collection certCollection = certs.getMatches(signer.getSID());

				Iterator certIt = certCollection.iterator();
				X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

				assertEquals(true, signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(cert)));
			}

			((FileBackedMimeBodyPart)mm).dispose();
		}

		public virtual void testSHA256WithRSAParserCompressed()
		{
			List certList = new ArrayList();

			certList.add(origCert);
			certList.add(signCert);

			Store certs = new JcaCertStore(certList);

			SMIMECompressedGenerator cGen = new SMIMECompressedGenerator();

			MimeBodyPart mp = cGen.generate(msg, new ZlibCompressor());

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider("BC").setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA256withRSA", origKP.getPrivate(), origCert));
			gen.addCertificates(certs);

			MimeMultipart smm = gen.generate(mp);
			File tmpFile = File.createTempFile("bcTest", ".mime");

			MimeMessage msg = createMimeMessage(tmpFile, smm);

			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider("BC").build(), (MimeMultipart)msg.getContent());

			certs = s.getCertificates();

			verifyMessageBytes(mp, s.getContent());

			verifySigners(certs, s.getSignerInfos());

			tmpFile.delete();
		}

		public virtual void testBrokenEnvelope()
		{
			Session session = Session.getDefaultInstance(System.getProperties(), null);
			MimeMessage msg = new MimeMessage(session, this.GetType().getResourceAsStream("brokenEnv.message"));

			try
			{
				new SMIMEEnveloped(msg);
			}
			catch (CMSException e)
			{
				if (!e.Message.Equals("Malformed content."))
				{
					fail("wrong exception on bogus envelope");
				}
			}
		}

		private void verifySigners(Store certs, SignerInformationStore signers)
		{
			Collection c = signers.getSigners();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();
				Collection certCollection = certs.getMatches(signer.getSID());

				Iterator certIt = certCollection.iterator();
				X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

				assertEquals(true, signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(cert)));
			}
		}

		private void verifyMessageBytes(MimeBodyPart a, MimeBodyPart b)
		{
			ByteArrayOutputStream bOut1 = new ByteArrayOutputStream();

			a.writeTo(bOut1);
			bOut1.close();

			ByteArrayOutputStream bOut2 = new ByteArrayOutputStream();

			b.writeTo(bOut2);
			bOut2.close();

			assertEquals(true, Arrays.Equals(bOut1.toByteArray(), bOut2.toByteArray()));
		}

		/// <summary>
		/// Create a mime message representing the multipart. We need to do
		/// this as otherwise no raw content stream for the message will exist.
		/// </summary>
		private MimeMessage createMimeMessage(File tmpFile, MimeMultipart smm)
		{
			FileOutputStream fOut = new FileOutputStream(tmpFile);
			Properties props = System.getProperties();
			Session session = Session.getDefaultInstance(props, null);

			Address fromUser = new InternetAddress(@"""Eric H. Echidna""<eric@bouncycastle.org>");
			Address toUser = new InternetAddress("example@bouncycastle.org");

			MimeMessage body = new MimeMessage(session);
			body.setFrom(fromUser);
			body.setRecipient(Message.RecipientType.TO, toUser);
			body.setSubject("example signed message");
			body.setContent(smm, smm.getContentType());
			body.saveChanges();

			body.writeTo(fOut);

			fOut.close();

			return new MimeMessage(session, new FileInputStream(tmpFile));
		}

		private ASN1EncodableVector generateSignedAttributes()
		{
			ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
			SMIMECapabilityVector caps = new SMIMECapabilityVector();

			caps.addCapability(SMIMECapability.dES_EDE3_CBC);
			caps.addCapability(SMIMECapability.rC2_CBC, 128);
			caps.addCapability(SMIMECapability.dES_CBC);

			signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

			return signedAttrs;
		}
	}

}