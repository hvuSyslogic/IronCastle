using org.bouncycastle.asn1.cms;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.cryptopro;

using System;
using System.Text;

namespace org.bouncycastle.mail.smime.test
{


	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSAttributes = org.bouncycastle.asn1.cms.CMSAttributes;
	using Time = org.bouncycastle.asn1.cms.Time;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SMIMECapabilitiesAttribute = org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
	using SMIMECapability = org.bouncycastle.asn1.smime.SMIMECapability;
	using SMIMECapabilityVector = org.bouncycastle.asn1.smime.SMIMECapabilityVector;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using X509AttributeCertificateHolder = org.bouncycastle.cert.X509AttributeCertificateHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaCertStore = org.bouncycastle.cert.jcajce.JcaCertStore;
	using DefaultSignedAttributeTableGenerator = org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using JcaSimpleSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using CRLFOutputStream = org.bouncycastle.mail.smime.util.CRLFOutputStream;
	using FileBackedMimeBodyPart = org.bouncycastle.mail.smime.util.FileBackedMimeBodyPart;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;
	using CollectionStore = org.bouncycastle.util.CollectionStore;
	using Store = org.bouncycastle.util.Store;

	public class NewSMIMESignedTest : TestCase
	{
		internal static MimeBodyPart msg;

		internal static MimeBodyPart msgR;
		internal static MimeBodyPart msgRN;

		internal static string _origDN;
		internal static KeyPair _origKP;
		internal static X509Certificate _origCert;

		internal static string _signDN;
		internal static KeyPair _signKP;
		internal static X509Certificate _signCert;

		internal static string reciDN;
		internal static KeyPair reciKP;
		internal static X509Certificate reciCert;

		private static KeyPair _signGostKP;
		private static X509Certificate _signGostCert;

		private static KeyPair _signEcDsaKP;
		private static X509Certificate _signEcDsaCert;

		private static KeyPair _signEcGostKP;
		private static X509Certificate _signEcGostCert;

		internal KeyPair dsaSignKP;
		internal X509Certificate dsaSignCert;

		internal KeyPair dsaOrigKP;
		internal X509Certificate dsaOrigCert;
		private const string BC = "BC";

		static NewSMIMESignedTest()
		{
			try
			{
				if (Security.getProvider("BC") == null)
				{
					Security.addProvider(new BouncyCastleProvider());
				}

				msg = SMIMETestUtil.makeMimeBodyPart("Hello world!\n");

				msgR = SMIMETestUtil.makeMimeBodyPart("Hello world!\r");
				msgRN = SMIMETestUtil.makeMimeBodyPart("Hello world!\r\n");

				_origDN = "O=Bouncy Castle, C=AU";
				_origKP = CMSTestUtil.makeKeyPair();
				_origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

				_signDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
				_signKP = CMSTestUtil.makeKeyPair();
				_signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);

				_signGostKP = CMSTestUtil.makeGostKeyPair();
				_signGostCert = CMSTestUtil.makeCertificate(_signGostKP, _signDN, _origKP, _origDN);

				_signEcDsaKP = CMSTestUtil.makeEcDsaKeyPair();
				_signEcDsaCert = CMSTestUtil.makeCertificate(_signEcDsaKP, _signDN, _origKP, _origDN);

				_signEcGostKP = CMSTestUtil.makeEcGostKeyPair();
				_signEcGostCert = CMSTestUtil.makeCertificate(_signEcGostKP, _signDN, _origKP, _origDN);
			}
			catch (Exception e)
			{
				throw new RuntimeException("problem setting up signed test class: " + e);
			}
				newline = new byte[2];
				newline[0] = 13;
				newline[1] = 10;
		}

		public class LineOutputStream : FilterOutputStream
		{
			internal static byte[] newline;

			public LineOutputStream(OutputStream outputstream) : base(outputstream)
			{
			}

			public virtual void writeln(string s)
			{
				try
				{
					byte[] abyte0 = getBytes(s);
					base.@out.write(abyte0);
					base.@out.write(newline);
				}
				catch (Exception exception)
				{
					throw new MessagingException("IOException", exception);
				}
			}

			public virtual void writeln()
			{
				try
				{
					base.@out.write(newline);
				}
				catch (Exception exception)
				{
					throw new MessagingException("IOException", exception);
				}
			}


			internal static byte[] getBytes(string s)
			{
				char[] ac = s.ToCharArray();
				int i = ac.Length;
				byte[] abyte0 = new byte[i];
				int j = 0;

				while (j < i)
				{
					abyte0[j] = (byte)ac[j++];
				}

				return abyte0;
			}
		}

		/*
		 *
		 *  INFRASTRUCTURE
		 *
		 */

		public NewSMIMESignedTest(string name) : base(name)
		{
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(typeof(NewSMIMESignedTest));
		}

		public static Test suite()
		{
			return new SMIMETestSetup(new TestSuite(typeof(NewSMIMESignedTest)));
		}

		public virtual void testHeaders()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			BodyPart bp = smm.getBodyPart(1);

			assertEquals("application/pkcs7-signature; name=smime.p7s; smime-type=signed-data", bp.getHeader("Content-Type")[0]);
			assertEquals(@"attachment; filename=""smime.p7s""", bp.getHeader("Content-Disposition")[0]);
			assertEquals("S/MIME Cryptographic Signature", bp.getHeader("Content-Description")[0]);
		}

		public virtual void testHeadersEncapsulated()
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA1withRSA", _signKP.getPrivate(), _signCert));

			gen.addCertificates(certs);

			MimeBodyPart res = gen.generateEncapsulated(msg);

			assertEquals("application/pkcs7-mime; name=smime.p7m; smime-type=signed-data", res.getHeader("Content-Type")[0]);
			assertEquals(@"attachment; filename=""smime.p7m""", res.getHeader("Content-Disposition")[0]);
			assertEquals("S/MIME Cryptographic Signed Data", res.getHeader("Content-Description")[0]);
		}

		public virtual void testMultipartTextText()
		{
			MimeBodyPart part1 = createTemplate("text/html", "7bit");
			MimeBodyPart part2 = createTemplate("text/xml", "7bit");

			multipartMixedTest(part1, part2);
		}

		public virtual void testMultipartTextBinary()
		{
			MimeBodyPart part1 = createTemplate("text/html", "7bit");
			MimeBodyPart part2 = createTemplate("text/xml", "binary");

			multipartMixedTest(part1, part2);
		}

		public virtual void testMultipartBinaryText()
		{
			MimeBodyPart part1 = createTemplate("text/xml", "binary");
			MimeBodyPart part2 = createTemplate("text/html", "7bit");

			multipartMixedTest(part1, part2);
		}

		public virtual void testMultipartBinaryBinary()
		{
			MimeBodyPart part1 = createTemplate("text/xml", "binary");
			MimeBodyPart part2 = createTemplate("text/html", "binary");

			multipartMixedTest(part1, part2);
		}

		public virtual void testSHA1WithRSAPSS()
		{
			rsaPSSTest("SHA1", SMIMESignedGenerator.DIGEST_SHA1);
		}

		public virtual void testSHA224WithRSAPSS()
		{
			rsaPSSTest("SHA224", SMIMESignedGenerator.DIGEST_SHA224);
		}

		public virtual void testSHA256WithRSAPSS()
		{
			rsaPSSTest("SHA256", SMIMESignedGenerator.DIGEST_SHA256);
		}

		public virtual void testSHA384WithRSAPSS()
		{
			rsaPSSTest("SHA384", SMIMESignedGenerator.DIGEST_SHA384);
		}

		public virtual void multipartMixedTest(MimeBodyPart part1, MimeBodyPart part2)
		{
			MimeMultipart mp = new MimeMultipart();

			mp.addBodyPart(part1);
			mp.addBodyPart(part2);

			MimeBodyPart m = new MimeBodyPart();

			m.setContent(mp);

			MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", m, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			verifySigners(s.getCertificates(), s.getSignerInfos());

			AttributeTable attr = ((SignerInformation)s.getSignerInfos().getSigners().iterator().next()).getSignedAttributes();

			Attribute a = attr.get(CMSAttributes_Fields.messageDigest);
			byte[] contentDigest = ASN1OctetString.getInstance(a.getAttrValues().getObjectAt(0)).getOctets();

			mp = (MimeMultipart)m.getContent();
			ContentType contentType = new ContentType(mp.getContentType());
			string boundary = "--" + contentType.getParameter("boundary");

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			LineOutputStream lOut = new LineOutputStream(bOut);

			Enumeration headers = m.getAllHeaderLines();
			while (headers.hasMoreElements())
			{
				lOut.writeln((string)headers.nextElement());
			}

			lOut.writeln(); // CRLF separator

			lOut.writeln(boundary);
			writePart(mp.getBodyPart(0), bOut);
			lOut.writeln(); // CRLF terminator

			lOut.writeln(boundary);
			writePart(mp.getBodyPart(1), bOut);
			lOut.writeln();

			lOut.writeln(boundary + "--");

			MessageDigest dig = MessageDigest.getInstance("SHA1", BC);

			assertTrue(Arrays.Equals(contentDigest, dig.digest(bOut.toByteArray())));
		}

		private void writePart(BodyPart part, ByteArrayOutputStream bOut)
		{
			if (part.getHeader("Content-Transfer-Encoding")[0].Equals("binary"))
			{
				part.writeTo(bOut);
			}
			else
			{
				part.writeTo(new CRLFOutputStream(bOut));
			}
		}

		public virtual void testSHA1WithRSA()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA1WithRSAAddSigners()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSigners(s.getSignerInfos());

			gen.addCertificates(certs);

			SMIMESigned newS = new SMIMESigned(gen.generate(msg));

			verifyMessageBytes(msg, newS.getContent());

			verifySigners(newS.getCertificates(), newS.getSignerInfos());
		}

		public virtual void testMD5WithRSAAddSignersSHA1()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.STANDARD_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("sha-1", getMicAlg(smm));

			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).build("MD5withRSA", _signKP.getPrivate(), _signCert));

			gen.addSigners(s.getSignerInfos());

			gen.addCertificates(certs);

			smm = gen.generate(msg);

			SMIMESigned newS = new SMIMESigned(gen.generate(msg));

			verifyMessageBytes(msg, newS.getContent());

			verifySigners(newS.getCertificates(), newS.getSignerInfos());

			assertEquals(@"""md5,sha-1""", getMicAlg(smm));
		}

		public virtual void testSHA1WithRSACanonicalization()
		{
			DateTime testTime = DateTime.Now;
			MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, testTime, SMIMESignedGenerator.RFC3851_MICALGS);

			byte[] sig1 = getEncodedStream(smm);

			smm = generateMultiPartRsa("SHA1withRSA", msgR, testTime, SMIMESignedGenerator.RFC3851_MICALGS);

			byte[] sig2 = getEncodedStream(smm);

			assertTrue(Arrays.Equals(sig1, sig2));

			smm = generateMultiPartRsa("SHA1withRSA", msgRN, testTime, SMIMESignedGenerator.RFC3851_MICALGS);

			byte[] sig3 = getEncodedStream(smm);

			assertTrue(Arrays.Equals(sig1, sig3));
		}

		private byte[] getEncodedStream(MimeMultipart smm)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			smm.getBodyPart(1).writeTo(bOut);

			return bOut.toByteArray();
		}

		public virtual void testSHA1WithRSAEncapsulated()
		{
			MimeBodyPart res = generateEncapsulatedRsa("SHA1withRSA", msg);
			SMIMESigned s = new SMIMESigned(res);

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA1WithRSAEncapsulatedParser()
		{
			MimeBodyPart res = generateEncapsulatedRsa("SHA1withRSA", msg);
			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), res);

			FileBackedMimeBodyPart content = (FileBackedMimeBodyPart)s.getContent();

			verifyMessageBytes(msg, content);

			content.dispose();

			verifySigners(s.getCertificates(), s.getSignerInfos());

			s.close();
		}

		public virtual void testSHA1WithRSAEncapsulatedParserAndFile()
		{
			File tmp = File.createTempFile("bcTest", ".mime");
			MimeBodyPart res = generateEncapsulatedRsa("SHA1withRSA", msg);
			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), res, tmp);
			FileBackedMimeBodyPart content = (FileBackedMimeBodyPart)s.getContent();

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());

			assertTrue(tmp.exists());

			s.close();

			content.dispose();

			assertFalse(tmp.exists());
		}

		public virtual void testMD5WithRSA()
		{
			MimeMultipart smm = generateMultiPartRsa("MD5withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("md5", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), PKCSObjectIdentifiers_Fields.md5.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA224WithRSA()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA224withRSA", msg, SMIMESignedGenerator.STANDARD_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("sha-224", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers_Fields.id_sha224.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA224WithRSARfc3851()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA224withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("sha224", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers_Fields.id_sha224.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA256WithRSA()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA256withRSA", msg, SMIMESignedGenerator.STANDARD_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("sha-256", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers_Fields.id_sha256.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA256WithRSARfc3851()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA256withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("sha256", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers_Fields.id_sha256.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA384WithRSA()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA384withRSA", msg, SMIMESignedGenerator.STANDARD_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("sha-384", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers_Fields.id_sha384.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA384WithRSARfc3851()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA384withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("sha384", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers_Fields.id_sha384.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA512WithRSA()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA512withRSA", msg, SMIMESignedGenerator.STANDARD_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("sha-512", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers_Fields.id_sha512.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA512WithRSARfc3851()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA512withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("sha512", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers_Fields.id_sha512.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testRIPEMD160WithRSA()
		{
			MimeMultipart smm = generateMultiPartRsa("RIPEMD160withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("unknown", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), TeleTrusTObjectIdentifiers_Fields.ripemd160.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testGOST3411WithGOST3410()
		{
			MimeMultipart smm = generateMultiPartGost(msg);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("gostr3411-94", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), CryptoProObjectIdentifiers_Fields.gostR3411.getId());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testGOST3411WithECGOST3410()
		{
			MimeMultipart smm = generateMultiPartECGost(msg);
			SMIMESigned s = new SMIMESigned(smm);

			assertEquals("gostr3411-94", getMicAlg(smm));
			assertEquals(getDigestOid(s.getSignerInfos()), CryptoProObjectIdentifiers_Fields.gostR3411.getId());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA224WithRSAParser()
		{
			MimeMultipart smm = generateMultiPartRsa("SHA224withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), smm);
			Store certs = s.getCertificates();

			assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers_Fields.id_sha224.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(certs, s.getSignerInfos());
		}

		public virtual void testSHA224WithRSAParserEncryptedWithDES()
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttrs))).build("SHA224withRSA", _signKP.getPrivate(), _signCert));
			gen.addCertificates(certs);

			MimeMultipart smm = gen.generate(msg);
			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), smm);

			certs = s.getCertificates();

			assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers_Fields.id_sha224.ToString());

			verifyMessageBytes(msg, s.getContent());

			verifySigners(certs, s.getSignerInfos());
		}

		public virtual void testSHA1withDSA()
		{
			dsaSignKP = CMSTestUtil.makeDsaKeyPair();
			dsaSignCert = CMSTestUtil.makeCertificate(dsaSignKP, _origDN, dsaSignKP, _origDN);

			dsaOrigKP = CMSTestUtil.makeDsaKeyPair();
			dsaOrigCert = CMSTestUtil.makeCertificate(dsaOrigKP, _signDN, dsaSignKP, _origDN);

			List certList = new ArrayList();

			certList.add(dsaOrigCert);
			certList.add(dsaSignCert);

			Store certs = new JcaCertStore(certList);

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider("BC").build("SHA1withDSA", dsaOrigKP.getPrivate(), dsaOrigCert));
			gen.addCertificates(certs);

			MimeMultipart smm = gen.generate(msg);
			SMIMESigned s = new SMIMESigned(smm);

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA256WithRSABinary()
		{
			MimeBodyPart msg = generateBinaryPart();
			MimeMultipart smm = generateMultiPartRsa("SHA256withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESigned s = new SMIMESigned(smm);

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testSHA256WithRSABinaryWithParser()
		{
			MimeBodyPart msg = generateBinaryPart();
			MimeMultipart smm = generateMultiPartRsa("SHA256withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), smm);

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testWithAttributeCertificate()
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttrs))).build("SHA256withRSA", _signKP.getPrivate(), _signCert));

			gen.addCertificates(certs);

			X509AttributeCertificateHolder attrCert = CMSTestUtil.getAttributeCertificate();

			List attrCertList = new ArrayList();

			attrCertList.add(attrCert);

			Store store = new CollectionStore(attrCertList);

			gen.addAttributeCertificates(store);

			SMIMESigned s = new SMIMESigned(gen.generateEncapsulated(msg));

			verifyMessageBytes(msg, s.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());

			Store attrCerts = s.getAttributeCertificates();

			assertTrue(attrCerts.getMatches(null).contains(attrCert));
		}

		private void rsaPSSTest(string digest, string digestOID)
		{
			MimeMultipart smm = generateMultiPartRsaPSS(digest, msg, null);
			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), smm);
			Store certs = s.getCertificates();

			assertEquals(getDigestOid(s.getSignerInfos()), digestOID);

			verifyMessageBytes(msg, s.getContent());

			verifySigners(certs, s.getSignerInfos());
		}

		private MimeBodyPart generateBinaryPart()
		{
			byte[] content = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 10, 11, 12, 13, 14, 10, 10, 15, 16};
			InternetHeaders ih = new InternetHeaders();

			ih.setHeader("Content-Transfer-Encoding", "binary");
			return new MimeBodyPart(ih, content);
		}

		private MimeMultipart generateMultiPartRsa(string algorithm, MimeBodyPart msg, DateTime signingTime, Map micalgs)
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			if (signingTime != null)
			{
				signedAttrs.add(new Attribute(CMSAttributes_Fields.signingTime, new DERSet(new Time(signingTime))));
			}

			SMIMESignedGenerator gen = new SMIMESignedGenerator(micalgs);

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttrs))).build(algorithm, _signKP.getPrivate(), _signCert));
			gen.addCertificates(certs);

			return gen.generate(msg);
		}

		private MimeMultipart generateMultiPartRsaPSS(string digest, MimeBodyPart msg, DateTime signingTime)
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			if (signingTime != null)
			{
				signedAttrs.add(new Attribute(CMSAttributes_Fields.signingTime, new DERSet(new Time(signingTime))));
			}

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build(digest + "withRSAandMGF1", _signKP.getPrivate(), _signCert));
			gen.addCertificates(certs);

			return gen.generate(msg);
		}

		private MimeMultipart generateMultiPartGost(MimeBodyPart msg)
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_signGostCert);

			Store certs = new JcaCertStore(certList);

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).build("GOST3411withGOST3410", _signGostKP.getPrivate(), _signGostCert));
			gen.addCertificates(certs);

			return gen.generate(msg);
		}

		private MimeMultipart generateMultiPartECGost(MimeBodyPart msg)
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_signEcGostCert);

			Store certs = new JcaCertStore(certList);

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).build("GOST3411withECGOST3410", _signEcGostKP.getPrivate(), _signEcGostCert));
			gen.addCertificates(certs);

			return gen.generate(msg);
		}

		private MimeMultipart generateMultiPartRsa(string algorithm, MimeBodyPart msg, Map micalgs)
		{
			return generateMultiPartRsa(algorithm, msg, null, micalgs);
		}

		private MimeBodyPart generateEncapsulatedRsa(string sigAlg, MimeBodyPart msg)
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build(sigAlg, _signKP.getPrivate(), _signCert));
			gen.addCertificates(certs);

			return gen.generateEncapsulated(msg);
		}

		public virtual void testCertificateManagement()
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addCertificates(certs);

			MimeBodyPart smm = gen.generateCertificateManagement();

			SMIMESigned s = new SMIMESigned(smm);

			certs = s.getCertificates();

			assertEquals(2, certs.getMatches(null).size());
		}

		public virtual void testMimeMultipart()
		{
			MimeBodyPart m = createMultipartMessage();

			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator("binary");

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA1withRSA", _signKP.getPrivate(), _signCert));
			gen.addCertificates(certs);

			MimeMultipart mm = gen.generate(m);

			SMIMESigned s = new SMIMESigned(mm);

			verifySigners(s.getCertificates(), s.getSignerInfos());

			byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(SMIMESignedGenerator.DIGEST_SHA1);

			AttributeTable table = ((SignerInformation)s.getSignerInfos().getSigners().iterator().next()).getSignedAttributes();
			Attribute hash = table.get(CMSAttributes_Fields.messageDigest);

			assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
		}

		public virtual void testMimeMultipartBinaryReader()
		{
			MimeBodyPart m = createMultipartMessage();

			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator("binary");

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA1withRSA", _signKP.getPrivate(), _signCert));
			gen.addCertificates(certs);

			MimeMultipart mm = gen.generate(m);

			SMIMESigned s = new SMIMESigned(mm, "binary");

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testMimeMultipartBinaryParser()
		{
			MimeBodyPart m = createMultipartMessage();

			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator("binary");

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA1withRSA", _signKP.getPrivate(), _signCert));
			gen.addCertificates(certs);

			MimeMultipart mm = gen.generate(m);

			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), mm, "binary");

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testMimeMultipartBinaryParserGetMimeContent()
		{
			MimeBodyPart m = createMultipartMessage();

			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator("binary");

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA1withRSA", _signKP.getPrivate(), _signCert));
			gen.addCertificates(certs);

			MimeMultipart mm = gen.generate(m);

			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), mm, "binary");

			verifySigners(s.getCertificates(), s.getSignerInfos());

			MimeMessage bp = s.getContentAsMimeMessage(Session.getDefaultInstance(new Properties()));
		}

		private MimeBodyPart createMultipartMessage()
		{
			MimeBodyPart msg1 = new MimeBodyPart();

			msg1.setText("Hello part 1!\n");

			MimeBodyPart msg2 = new MimeBodyPart();

			msg2.setText("Hello part 2!\n");

			MimeMultipart mp = new MimeMultipart();

			mp.addBodyPart(msg1);
			mp.addBodyPart(msg2);

			MimeBodyPart m = new MimeBodyPart();

			m.setContent(mp);

			return m;
		}

		public virtual void testQuotable()
		{
			MimeMessage message = loadMessage("quotable.message");

			SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testQuotableParser()
		{
			MimeMessage message = loadMessage("quotable.message");

			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), (MimeMultipart)message.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testEmbeddedMulti()
		{
			MimeMessage message = loadMessage("embeddedmulti.message");

			SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testEmbeddedMultiParser()
		{
			MimeMessage message = loadMessage("embeddedmulti.message");

			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), (MimeMultipart)message.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testPSSVariantSalt()
		{
			bool skip = false;

			try
			{
				// no can do on 1.3
				this.GetType().getClassLoader().loadClass("java.security.spec.PSSParameterSpec");
			}
			catch (Exception)
			{
				skip = true;
			}

			if (!skip)
			{
				MimeMessage message = loadMessage("openssl-signed-sha256-non-default-salt-length.eml");

				SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

				verifySigners(s.getCertificates(), s.getSignerInfos());
			}
		}

		public virtual void testMultiAlternative()
		{
			MimeMessage message = loadMessage("multi-alternative.eml");

			SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testExtraNlInPostamble()
		{
			MimeMessage message = loadMessage("extra-nl.eml");

			SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testDoubleNlCanonical()
		{
			MimeMessage message = loadMessage("3nnn_smime.eml");

			SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

			Collection c = s.getSignerInfos().getSigners();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();
				Collection certCollection = s.getCertificates().getMatches(signer.getSID());

				Iterator certIt = certCollection.iterator();
				X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

				// in this case the sig is invalid, but it's the lack of an exception from the content digest we're looking for
				assertFalse(signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(certHolder)));
			}
		}

		public virtual void testSignAttachmentOnly()
		{
			MimeMessage m = loadMessage("attachonly.eml");

			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			ASN1EncodableVector signedAttrs = generateSignedAttributes();

			SMIMESignedGenerator gen = new SMIMESignedGenerator("binary");

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA1withRSA", _signKP.getPrivate(), _signCert));
			gen.addCertificates(certs);

			MimeMultipart mm = gen.generate(m);

			SMIMESigned s = new SMIMESigned(mm);

			verifySigners(s.getCertificates(), s.getSignerInfos());

			SMIMESignedParser sp = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), mm);

			verifySigners(sp.getCertificates(), sp.getSignerInfos());
		}

		public virtual void testMultiAlternativeParser()
		{
			MimeMessage message = loadMessage("multi-alternative.eml");

			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), (MimeMultipart)message.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testBasicAS2()
		{
			MimeMessage message = loadMessage("basicAS2.message");

			SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testBasicAS2Parser()
		{
			MimeMessage message = loadMessage("basicAS2.message");

			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), (MimeMultipart)message.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		public virtual void testRawAS2Parser()
		{
			MimeMessage message = loadMessage("rawAS2.message");

			SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build(), (MimeMultipart)message.getContent());

			verifySigners(s.getCertificates(), s.getSignerInfos());
		}

		private string getDigestOid(SignerInformationStore s)
		{
			return ((SignerInformation)s.getSigners().iterator().next()).getDigestAlgOID();
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
				X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

				assertEquals(true, signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(certHolder)));
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

		private MimeMessage loadMessage(string name)
		{
			Session session = Session.getDefaultInstance(System.getProperties(), null);

			return new MimeMessage(session, this.GetType().getResourceAsStream(name));
		}

		private MimeBodyPart createTemplate(string contentType, string contentTransferEncoding)
		{
			byte[] content = @"<?xml version=""1.0""?>\n<INVOICE_CENTER>\n  <CONTENT_FRAME>\n</CONTENT_FRAME>\n</INVOICE_CENTER>\n".GetBytes(Encoding.ASCII);

			InternetHeaders ih = new InternetHeaders();
			ih.setHeader("Content-Type", contentType);
			ih.setHeader("Content-Transfer-Encoding", contentTransferEncoding);

			return new MimeBodyPart(ih, content);
		}

		private string getMicAlg(MimeMultipart mm)
		{
			string contentType = mm.getContentType();
			string micAlg = contentType.Substring(contentType.IndexOf("micalg=", StringComparison.Ordinal) + 7);

			return micAlg.Substring(0, micAlg.IndexOf(';'));
		}
	}

}