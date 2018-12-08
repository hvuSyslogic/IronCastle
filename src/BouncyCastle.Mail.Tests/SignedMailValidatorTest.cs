using org.bouncycastle.asn1;
using org.bouncycastle.jce.provider;

namespace org.bouncycastle.mail.smime.test
{


	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using JcaCertStore = org.bouncycastle.cert.jcajce.JcaCertStore;
	using JcaX509ExtensionUtils = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using JcaSimpleSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
	using ErrorBundle = org.bouncycastle.i18n.ErrorBundle;
	using SignedMailValidator = org.bouncycastle.mail.smime.validator.SignedMailValidator;
	using Store = org.bouncycastle.util.Store;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using PKIXCertPathReviewer = org.bouncycastle.x509.PKIXCertPathReviewer;

	public class SignedMailValidatorTest : TestCase
	{
		internal static string TEST_TRUST_ACHOR = "validator.root.crt";

		internal static byte[] multiEmailCert = Base64.decode("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdmVENDQkdXZ0F3SUJB" + "Z0lCR2pBTkJna3Foa2lHOXcwQkFRc0ZBRENCdnpFTE1Ba0dBMVVFQmhNQ1Ew" + "Z3gKQ3pBSkJnTlZCQWdUQWxwSU1ROHdEUVlEVlFRSEV3WmFkWEpwWTJneEZ6" + "QVZCZ05WQkFvVERsQnlhWFpoVTNCbwpaWEpsSUVGSE1SNHdIQVlEVlFRTERC" + "VkVaWFpsYkc5d2JXVnVkQ0FtSUZSbGMzUnBibWN4TkRBeUJnTlZCQU1NCksx" + "QnlhWFpoVTNCb1pYSmxJRWx1ZEdWeWJXVmthV0Z5ZVNCRFpYSjBhV1pwWTJG" + "MFpTQmJWRVZUVkYweEl6QWgKQmdrcWhraUc5dzBCQ1FFV0ZHbHVabTlBY0hK" + "cGRtRnpjR2hsY21VdVkyOXRNQjRYRFRFM01EWXlPREE0TkRjdwpNRm9YRFRN" + "M01EWXlPREE0TkRjd01Gb3dnZDB4Q3pBSkJnTlZCQVlUQWtOSU1Rc3dDUVlE" + "VlFRSUV3SmFTREVQCk1BMEdBMVVFQnhNR1duVnlhV05vTVJjd0ZRWURWUVFL" + "RXc1UWNtbDJZVk53YUdWeVpTQkJSekVlTUJ3R0ExVUUKQ3d3VlJHVjJaV3h2" + "Y0cxbGJuUWdKaUJVWlhOMGFXNW5NVGd3TmdZSktvWklodmNOQVFrQkZpbGti" + "MjFoYVc0dApZMjl1Wm1sa1pXNTBhV0ZzYVhSNUxXRjFkR2h2Y21sMGVVQmla" + "V3RpTG1Ob0lERTlNRHNHQ1NxR1NJYjNEUUVKCkFSWXVaRzl0WVdsdUxXTnZi" + "bVpwWkdWdWRHbGhiR2wwZVMxaGRYUm9iM0pwZEhsQVptRnRhV3g1TFc1bGRD" + "NWoKYURDQ0FpSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnSVBBRENDQWdvQ2dn" + "SUJBTWJmNEh2a0lYUHpta1BTR09JbApxZ0FhdWlOYVVNdGNPSFlvWnBrS2dt" + "ekVsdk4xNnk5enYyZUNkdThnTGNaT3FXT2ZNNmkzY0Z6T1N0bEIxL2lDClM4" + "Vks2ekJmRUgrcDlBbFBCaFVKMDBrbjRESVNXSmRiV25pWXM2clo2cWtpTjZi" + "aHV6V3k5YTVsZkM0c3Q2UisKN0lVcWJwaGxQSUU5OEhJbmQxV01ieTZKYWV0" + "WHNZbW5Sb1Mxd29Fblg5U1BDdXBSK1dzbmtOemtRTFFhMGJYaApVZ3ZmR0Zh" + "VTJwWXBLdXdvN3BsdHBZQzJjVENtVmFJR05rVmJWVGFsYktub0VoNVgrelRq" + "U2oxSWJLaVdIVmNMCjJGTkxoS1hBS1loRGNXd2llVVd0S281T2JrWTZWRzVj" + "dnU0OVozc1llUkkzNnZwY0NNTklvRzFJWlQ1bnhhVmYKKzlaRTM0WllOV3Y4" + "RHZXOFdHZzc4RmkxS1dzanlCajN0SDk3Q3lIZnRsdFl3U3REVXllaGZHUytp" + "aTBteUVWSwpzQ1BiQmwvOU82VHhISWZNRDVuTjlGeFZSZENrdTM5U1hmK29R" + "K3pNdEE0eEtyc3JLVm9RUGZvNDhYaW5HMStICmxZWW1HL01SYTkzZHFCd1ov" + "ZEUrRnZLZ2hmU003bVRPTEhPa0YxL0RzQnRJb0s4YmMrRDBIVHhZbWlsbFRj" + "Vm0KbFkrVnArRHdtdStRVXlvOFU5UmU3Q0ZOOGs5RlVtc2hORTcyRDkvNytM" + "NmI0Smt0ZTQvdXlzOGVIYnVoRXBnNQphTVMySHRjSkRJL25LbEE2TjFWZjVx" + "aVlaVnIrUkRPZmxmS3ZHdnVGcFFMcjhWUUFONFUzalhOaVVIRGI2ek9rCms5" + "UWdpV2REWDJrTFRTeldubnI5ZDFYTkFnTUJBQUdqWkRCaU1Bd0dBMVVkRXdF" + "Qi93UUNNQUF3Q3dZRFZSMFAKQkFRREFnYkFNQk1HQTFVZEpRUU1NQW9HQ0Nz" + "R0FRVUZCd01FTUJFR0NXQ0dTQUdHK0VJQkFRUUVBd0lGSURBZApCZ2xnaGtn" + "Qmh2aENBUTBFRUJZT1VISnBkbUZUY0dobGNtVWdRMEV3RFFZSktvWklodmNO" + "QVFFTEJRQURnZ0lCCkFONjF2Sy9taFhCc3NHZEpxTGszVjBOK3BJOFRRc3ps" + "RU5pbzJTQ25kSTZyejhRRzFnUVBRZjRIaCtIZUNpWFYKNVlIcHAxMjdZVXlR" + "Y1hiK3JYc3lSQXM0SWd6TWZyK3dmTWY5NVdianQ1QWRVR21XdFdwV2pkajBo" + "YmlROGJmMwprU3Y4TnR6ZVhKTHBOYS9YK0NRYy9vRm1qeHZ1ZDJXczVzZG1S" + "Uno2VUlKVFJoT2t4SFErTVlqL1NlTFFIQWU3CkQzaFV5NE9iVnlBU3VLaHpH" + "MnExYm9mSnBKZHByZVNSMll2a2JQRW9FRlZSd2NQTXNPMFdGRmpCSGlHbVln" + "aTEKd21qTnlzak8wZ0lwNnpMUzNSSUErd1llRHJVVnEzSnRya0RJZnZkL2tS" + "T2UvcUFlcDB3THRReGFoSEFOSk80UAo5ZmxtV1F6bENMRlFoTUZibFl2Nis1" + "NVVDeDhvRkVJTmUvaWF1VUlZME54WXZWclBMREwwVFhSR3grdVFsVVJaCkZi" + "SUpBYzBTUW1SWXlHVkdnb1pUbVhHd0FjemNLWk5XZzd6NTk5TXBidW13ejJZ" + "T2RTekRncjV0MHpGQUhDRG8KanRuUnRudVRYMkxvK1UwaWF6RlZhNVYrbDVs" + "QjNIdFpXOWJkKy9ZSVo5K3YyZWpOS3M4UzZjQW1DRkFmVWpkUgpvWEJQUVdP" + "Tmx6MjdGOXc3ajc5dmlNUHVES0ZtOU9LdmhQdVQvdWVaOGJCNmRYMlh3aTNw" + "RTM1dWdRK05NT1crCnFUSkZSNDhyVzFvRkYxNTdxNXFzU2ovK3lqQlZpejRL" + "YWlDakVKRDR4RE1UNzAzQytsTGZyamk3KzR2Z3ZIV0IKbHNCVS9jWkVoeFdu" + "VjJQaHRsR3g2M2s2OThYeU03eWFCcDUvdHZuL2xSY0cKLS0tLS1FTkQgQ0VS" + "VElGSUNBVEUtLS0tLQo=");

		public virtual void testShortKey()
		{
			string message = "validator.shortKey.eml";
			PKIXParameters @params = createDefaultParams();
			SignedMailValidator.ValidationResult result = doTest(message, @params);

			assertTrue(result.isValidSignature());
			assertContainsMessage(result.getNotifications(), "SignedMailValidator.shortSigningKey", "Warning: The signing key is only 512 bits long.");
		}

		public virtual void testKeyUsage()
		{
			string message = "validator.keyUsage.eml";
			PKIXParameters @params = createDefaultParams();
			SignedMailValidator.ValidationResult result = doTest(message, @params);

			assertTrue(result.isVerifiedSignature());
			assertTrue(result.getCertPathReview().isValidCertPath());
			assertFalse(result.isValidSignature());

			assertContainsMessage(result.getErrors(), "SignedMailValidator.signingNotPermitted", "The key usage extension of signer certificate does not permit using the key for email signatures.");
		}

		public virtual void testMultiEmail()
		{
			CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");

			Set addresses = SignedMailValidator.getEmailAddresses((X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(multiEmailCert)));

			assertTrue(addresses.contains("domain-confidentiality-authority@family-net.ch"));
			assertTrue(addresses.contains("domain-confidentiality-authority@bekb.ch "));
		}

		public virtual void testExtKeyUsage()
		{
			string message = "validator.extKeyUsage.eml";
			PKIXParameters @params = createDefaultParams();
			SignedMailValidator.ValidationResult result = doTest(message, @params);

			assertTrue(result.isVerifiedSignature());
			assertTrue(result.getCertPathReview().isValidCertPath());
			assertFalse(result.isValidSignature());

			assertContainsMessage(result.getErrors(), "SignedMailValidator.extKeyUsageNotPermitted", "The extended key usage extension of the signer certificate does not permit using the key for email signatures.");
		}

		public virtual void testNoEmail()
		{
			string message = "validator.noEmail.eml";
			PKIXParameters @params = createDefaultParams();
			SignedMailValidator.ValidationResult result = doTest(message, @params);

			assertTrue(result.isVerifiedSignature());
			assertTrue(result.getCertPathReview().isValidCertPath());
			assertFalse(result.isValidSignature());

			assertContainsMessage(result.getErrors(), "SignedMailValidator.noEmailInCert", "The signer certificate is not usable for email signatures: it contains no email address.");
		}

		public virtual void testNotYetValid()
		{
			string message = "validator.notYetValid.eml";
			PKIXParameters @params = createDefaultParams();
			SignedMailValidator.ValidationResult result = doTest(message, @params);

			assertTrue(result.isVerifiedSignature());
			assertFalse(result.isValidSignature());
			assertContainsMessage(result.getErrors(), "SignedMailValidator.certNotYetValid", "The message was signed at Aug 28, 2006 3:04:01 PM GMT. But the certificate is not valid before Dec 28, 2006 2:19:31 PM GMT.");

			PKIXCertPathReviewer review = result.getCertPathReview();
			assertFalse(review.isValidCertPath());
			assertContainsMessage(review.getErrors(0), "CertPathReviewer.certificateNotYetValid", "Could not validate the certificate. Certificate is not valid until Dec 28, 2006 2:19:31 PM GMT.");
		}

		public virtual void testExpired()
		{
			string message = "validator.expired.eml";
			PKIXParameters @params = createDefaultParams();
			SignedMailValidator.ValidationResult result = doTest(message, @params);

			assertTrue(result.isVerifiedSignature());
			assertFalse(result.isValidSignature());
			assertContainsMessage(result.getErrors(), "SignedMailValidator.certExpired", "The message was signed at Sep 1, 2006 9:08:35 AM GMT. But the certificate expired at Sep 1, 2006 8:39:20 AM GMT.");

			PKIXCertPathReviewer review = result.getCertPathReview();
			assertFalse(review.isValidCertPath());
			assertContainsMessage(review.getErrors(0), "CertPathReviewer.certificateExpired", "Could not validate the certificate. Certificate expired on Sep 1, 2006 8:39:20 AM GMT.");
		}

		public virtual void testRevoked()
		{
			string message = "validator.revoked.eml";
			PKIXParameters @params = createDefaultParams();
			List crlList = new ArrayList();
			crlList.add(loadCRL("validator.revoked.crl"));
			CertStore crls = CertStore.getInstance("Collection",new CollectionCertStoreParameters(crlList));
			@params.addCertStore(crls);
			@params.setRevocationEnabled(true);

			SignedMailValidator.ValidationResult result = doTest(message, @params);

			assertTrue(result.isVerifiedSignature());
			assertFalse(result.isValidSignature());

			PKIXCertPathReviewer review = result.getCertPathReview();
			assertFalse(review.isValidCertPath());
			assertContainsMessage(review.getErrors(0), "CertPathReviewer.certRevoked", "The certificate was revoked at Sep 1, 2006 9:30:00 AM GMT. Reason: Key Compromise.");
		}

		public virtual void testLongValidity()
		{
			string message = "validator.longValidity.eml";
			PKIXParameters @params = createDefaultParams();

			SignedMailValidator.ValidationResult result = doTest(message, @params);

			assertTrue(result.isVerifiedSignature());
			assertTrue(result.isValidSignature());

			assertContainsMessage(result.getNotifications(), "SignedMailValidator.longValidity", "Warning: The signing certificate has a very long validity period: from Sep 1, 2006 11:00:00 AM GMT until Aug 8, 2106 11:00:00 AM GMT.");
		}

		public virtual void testSelfSignedCert()
		{
			MimeBodyPart baseMsg = SMIMETestUtil.makeMimeBodyPart("Hello world!\n");
			string signDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
			KeyPair signKP = CMSTestUtil.makeKeyPair();
			X509Certificate signCert = CMSTestUtil.makeV1Certificate(signKP, signDN, signKP, signDN);

			// check basic path validation
			Set trustanchors = new HashSet();
			TrustAnchor ta = new TrustAnchor(signCert, null);
			trustanchors.add(ta);

			X509Certificate rootCert = ta.getTrustedCert();

			// init cert stores
			List certStores = new ArrayList();
			List certList = new ArrayList();
			certList.add(rootCert);
			CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
			certStores.add(store);

			// first path
			CertPath path = SignedMailValidator.createCertPath(rootCert, trustanchors, certStores);

			assertTrue("path size is not 1", path.getCertificates().size() == 1);

			// check message validation
			certList = new ArrayList();

			certList.add(signCert);

			Store certs = new JcaCertStore(certList);

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider("BC").build("SHA1withRSA", signKP.getPrivate(), signCert));
			gen.addCertificates(certs);

			MimeMultipart signedMsg = gen.generate(baseMsg);

			Properties props = System.getProperties();
			Session session = Session.getDefaultInstance(props, null);

			// read message
			MimeMessage msg = new MimeMessage(session);

			Address fromUser = new InternetAddress(@"""Eric H. Echidna""<eric@bouncycastle.org>");
			Address toUser = new InternetAddress("example@bouncycastle.org");

			msg.setFrom(fromUser);
			msg.setRecipient(Message.RecipientType.TO, toUser);
			msg.setContent(signedMsg, signedMsg.getContentType());

			msg.saveChanges();

			PKIXParameters @params = new PKIXParameters(trustanchors);
			@params.setRevocationEnabled(false);

			SignedMailValidator validator = new SignedMailValidator(msg, @params);
			SignerInformation signer = (SignerInformation) validator.getSignerInformationStore().getSigners().iterator().next();

			SignedMailValidator.ValidationResult res = validator.getValidationResult(signer);

			assertTrue(res.isVerifiedSignature());
			assertTrue(res.isValidSignature());
		}

	// TODO: this test needs to be replaced, unfortunately it was working due to a bug in
	// trust anchor extension handling
	//    public void testCorruptRootStore() throws Exception
	//    {
	//        String message = "validator.validMail.eml";
	//        Set trustanchors = new HashSet();
	//        trustanchors.add(getTrustAnchor(TEST_TRUST_ACHOR));
	//        trustanchors.add(getTrustAnchor("validator.fakeRoot.crt"));
	//        PKIXParameters params = new PKIXParameters(trustanchors);
	//        params.setRevocationEnabled(false);
	//
	//        SignedMailValidator.ValidationResult result = doTest(message, params);
	//
	//        assertTrue(result.isVerifiedSignature());
	//        assertFalse(result.isValidSignature());
	//
	//        PKIXCertPathReviewer review = result.getCertPathReview();
	//
	//        assertFalse(review.isValidCertPath());
	//        assertContainsMessage(review.getErrors(-1),
	//                "CertPathReviewer.conflictingTrustAnchors",
	//                "Warning: corrupt trust root store: There are 2 trusted public keys for the CA \"CN=SignedMailValidatorTest Root, C=CH\" - please ensure with CA which is the correct key.");
	//    }

		public virtual void testCircular()
		{
			string message = "circular.eml";
			PKIXParameters @params = createDefaultParams();
			SignedMailValidator.ValidationResult result = doTest(message, @params);

			assertTrue(result.isVerifiedSignature());
			assertFalse(result.isValidSignature());
			assertFalse(result.getCertPathReview().isValidCertPath());
			assertTrue("cert path size", result.getCertPathReview().getCertPathSize() > 2);
		}

		public virtual void testExtendedReviewer()
		{
			try
			{
				// Get a Session object with the default properties.
				Properties props = System.getProperties();
				Session session = Session.getDefaultInstance(props, null);

				// read message
				MimeMessage msg = new MimeMessage(session, this.GetType().getResourceAsStream("validator.shortKey.eml"));

				SignedMailValidator validator = new SignedMailValidator(msg, createDefaultParams(), typeof(string));
				fail();
			}
			catch (IllegalArgumentException e)
			{
				assertTrue(e.getMessage().StartsWith("certPathReviewerClass is not a subclass of"));
			}

			// Get a Session object with the default properties.
			Properties props = System.getProperties();
			Session session = Session.getDefaultInstance(props, null);

			// read message
			MimeMessage msg = new MimeMessage(session, this.GetType().getResourceAsStream("validator.shortKey.eml"));

			SignedMailValidator validator = new SignedMailValidator(msg, createDefaultParams(), typeof(DummyCertPathReviewer));
			SignerInformation sInfo = (SignerInformation) validator.getSignerInformationStore().getSigners().iterator().next();
			SignedMailValidator.ValidationResult result = validator.getValidationResult(sInfo);

			assertTrue(result.isValidSignature());
			assertContainsMessage(result.getNotifications(), "SignedMailValidator.shortSigningKey", "Warning: The signing key is only 512 bits long.");
		}

		public virtual void testCreateCertPath()
		{
			// load trust anchor
			Set trustanchors = new HashSet();
			TrustAnchor ta = getTrustAnchor("certpath_root.crt");
			trustanchors.add(ta);

			X509Certificate rootCert = ta.getTrustedCert();
			X509Certificate interCert1 = loadCert("certpath_inter1.crt");
			X509Certificate interCert2 = loadCert("certpath_inter2.crt");
			X509Certificate endCert1 = loadCert("certpath_end1.crt");
			X509Certificate endCert2 = loadCert("certpath_end2.crt");

			// init cert stores
			List certStores = new ArrayList();
			List certList = new ArrayList();
			certList.add(interCert1);
			certList.add(interCert2);
			CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
			certStores.add(store);

			// first path
			CertPath path = SignedMailValidator.createCertPath(endCert1, trustanchors, certStores);
			assertTrue("path size is not 3", path.getCertificates().size() == 3);
			assertEquals("different end certificate", path.getCertificates().get(0), endCert1);
			assertEquals("different intermediate certificate", path.getCertificates().get(1), interCert1);
			assertEquals("different root certificate", path.getCertificates().get(2), rootCert);

			// second path
			path = SignedMailValidator.createCertPath(endCert2, trustanchors, certStores);
			assertTrue("path size is not 3", path.getCertificates().size() == 3);
			assertEquals("different end certificate", path.getCertificates().get(0), endCert2);
			assertEquals("different intermediate certificate", path.getCertificates().get(1), interCert2);
			assertEquals("different root certificate", path.getCertificates().get(2), rootCert);
		}

		private SignedMailValidator.ValidationResult doTest(string message, PKIXParameters @params)
		{
			// Get a Session object with the default properties.
			Properties props = System.getProperties();
			Session session = Session.getDefaultInstance(props, null);

			// read message
			MimeMessage msg = new MimeMessage(session, this.GetType().getResourceAsStream(message));

			SignedMailValidator validator = new SignedMailValidator(msg, @params);
			SignerInformation signer = (SignerInformation) validator.getSignerInformationStore().getSigners().iterator().next();
			return validator.getValidationResult(signer);
		}

		private void assertContainsMessage(List msgList, string messageId, string text)
		{
			Iterator it = msgList.iterator();
			bool found = false;
			while (it.hasNext())
			{
				ErrorBundle message = (ErrorBundle) it.next();
				if (message.getId().Equals(messageId))
				{
					found = true;
					assertEquals(text, message.getText(Locale.ENGLISH, TimeZone.getTimeZone("GMT")));
					break;
				}
			}
			assertTrue("Expected message not found!", found);
		}

		private PKIXParameters createDefaultParams()
		{
			Set trustanchors = new HashSet();
			trustanchors.add(getTrustAnchor(TEST_TRUST_ACHOR));
			PKIXParameters defParams = new PKIXParameters(trustanchors);
			defParams.setRevocationEnabled(false);

			return defParams;
		}

		private TrustAnchor getTrustAnchor(string trustcert)
		{
			X509Certificate cert = loadCert(trustcert);
			if (cert != null)
			{
				byte[] ncBytes = cert.getExtensionValue(Extension.nameConstraints.getId());

				if (ncBytes != null)
				{
					ASN1Encodable extValue = JcaX509ExtensionUtils.parseExtensionValue(ncBytes);
					return new TrustAnchor(cert, extValue.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER));
				}
				return new TrustAnchor(cert, null);
			}
			return null;
		}

		private X509Certificate loadCert(string certfile)
		{
			X509Certificate cert = null;
			InputStream @in = this.GetType().getResourceAsStream(certfile);

			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
			cert = (X509Certificate) cf.generateCertificate(@in);
			return cert;
		}

		private X509CRL loadCRL(string crlfile)
		{
			X509CRL crl = null;
			InputStream @in = this.GetType().getResourceAsStream(crlfile);

			CertificateFactory cf = CertificateFactory.getInstance("x.509", "BC");
			crl = (X509CRL) cf.generateCRL(@in);
			return crl;
		}

		public virtual void setUp()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("SignedMailValidator Tests");

			suite.addTestSuite(typeof(SignedMailValidatorTest));

			return suite;
		}

	}

}