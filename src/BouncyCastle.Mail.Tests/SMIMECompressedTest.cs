using System;

namespace org.bouncycastle.mail.smime.test
{


	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using SMIMECapabilitiesAttribute = org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
	using SMIMECapability = org.bouncycastle.asn1.smime.SMIMECapability;
	using SMIMECapabilityVector = org.bouncycastle.asn1.smime.SMIMECapabilityVector;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaCertStore = org.bouncycastle.cert.jcajce.JcaCertStore;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using JcaSimpleSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using JcaX509CertSelectorConverter = org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
	using ZlibCompressor = org.bouncycastle.cms.jcajce.ZlibCompressor;
	using ZlibExpanderProvider = org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Arrays = org.bouncycastle.util.Arrays;
	using Store = org.bouncycastle.util.Store;

	public class SMIMECompressedTest : TestCase
	{
		private const string COMPRESSED_CONTENT_TYPE = @"application/pkcs7-mime; name=""smime.p7z""; smime-type=compressed-data";

		private static readonly JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

		private static MimeBodyPart msg;

		private static string signDN;
		private static KeyPair signKP;
		private static X509Certificate signCert;

		private static string origDN;
		private static KeyPair origKP;
		private static X509Certificate origCert;

		static SMIMECompressedTest()
		{
			try
			{
				if (Security.getProvider("BC") == null)
				{
					Security.addProvider(new BouncyCastleProvider());
				}

				msg = SMIMETestUtil.makeMimeBodyPart("Hello world!");

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

		public SMIMECompressedTest(string name) : base(name)
		{
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(typeof(SMIMECompressedTest));
		}

		public static Test suite()
		{
			return new SMIMETestSetup(new TestSuite(typeof(SMIMECompressedTest)));
		}

		public virtual void testHeaders()
		{
			SMIMECompressedGenerator cgen = new SMIMECompressedGenerator();

			MimeBodyPart cbp = cgen.generate(msg, new ZlibCompressor());

			assertEquals(COMPRESSED_CONTENT_TYPE, cbp.getHeader("Content-Type")[0]);
			assertEquals(@"attachment; filename=""smime.p7z""", cbp.getHeader("Content-Disposition")[0]);
			assertEquals("S/MIME Compressed Message", cbp.getHeader("Content-Description")[0]);
		}

		public virtual void testBasic()
		{
			SMIMECompressedGenerator cgen = new SMIMECompressedGenerator();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			MimeBodyPart cbp = cgen.generate(msg, new ZlibCompressor());

			SMIMECompressed sc = new SMIMECompressed(cbp);

			msg.writeTo(bOut);

			assertTrue(Arrays.areEqual(bOut.toByteArray(), sc.getContent(new ZlibExpanderProvider())));
		}

		public virtual void testParser()
		{
			SMIMECompressedGenerator cgen = new SMIMECompressedGenerator();
			ByteArrayOutputStream bOut1 = new ByteArrayOutputStream();
			ByteArrayOutputStream bOut2 = new ByteArrayOutputStream();
			MimeBodyPart cbp = cgen.generate(msg, new ZlibCompressor());
			SMIMECompressedParser sc = new SMIMECompressedParser(cbp);

			msg.writeTo(bOut1);

			InputStream @in = sc.getContent(new ZlibExpanderProvider()).getContentStream();
			int ch;

			while ((ch = @in.read()) >= 0)
			{
				bOut2.write(ch);
			}

			assertTrue(Arrays.areEqual(bOut1.toByteArray(), bOut2.toByteArray()));
		}

		/*
		 * test compressing and uncompressing of a multipart-signed message.
		 */
		public virtual void testCompressedSHA1WithRSA()
		{
			List certList = new ArrayList();

			certList.add(origCert);
			certList.add(signCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
			SMIMECapabilityVector caps = new SMIMECapabilityVector();

			caps.addCapability(SMIMECapability.dES_EDE3_CBC);
			caps.addCapability(SMIMECapability.rC2_CBC, 128);
			caps.addCapability(SMIMECapability.dES_CBC);

			signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider("BC").setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA1withRSA", origKP.getPrivate(), origCert));

			gen.addCertificates(certs);

			MimeMultipart smp = gen.generate(msg);

			MimeMessage bp2 = new MimeMessage((Session)null);

			bp2.setContent(smp);

			bp2.saveChanges();

			SMIMECompressedGenerator cgen = new SMIMECompressedGenerator();

			MimeBodyPart cbp = cgen.generate(bp2, new ZlibCompressor());

			SMIMECompressed cm = new SMIMECompressed(cbp);

			MimeMultipart mm = (MimeMultipart)SMIMEUtil.toMimeBodyPart(cm.getContent(new ZlibExpanderProvider())).getContent();

			SMIMESigned s = new SMIMESigned(mm);

			ByteArrayOutputStream _baos = new ByteArrayOutputStream();
			msg.writeTo(_baos);
			_baos.close();
			byte[] _msgBytes = _baos.toByteArray();
			_baos = new ByteArrayOutputStream();
			s.getContent().writeTo(_baos);
			_baos.close();
			byte[] _resBytes = _baos.toByteArray();

			assertEquals(true, Arrays.areEqual(_msgBytes, _resBytes));

			certs = s.getCertificates();

			SignerInformationStore signers = s.getSignerInfos();
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
	}

}