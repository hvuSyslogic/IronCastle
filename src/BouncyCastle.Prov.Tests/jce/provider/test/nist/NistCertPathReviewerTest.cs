using org.bouncycastle.asn1;
using org.bouncycastle.jce.provider;

using System;

namespace org.bouncycastle.jce.provider.test.nist
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using X509Extension = org.bouncycastle.asn1.x509.X509Extension;
	using ErrorBundle = org.bouncycastle.i18n.ErrorBundle;
	using PKIXCertPathReviewer = org.bouncycastle.x509.PKIXCertPathReviewer;
	using X509ExtensionUtil = org.bouncycastle.x509.extension.X509ExtensionUtil;

	/// <summary>
	/// NIST CertPath test data for RFC 3280
	/// </summary>
	public class NistCertPathReviewerTest : TestCase
	{
		private const string TEST_DATA_HOME = "bc.test.data.home";

		private const string GOOD_CA_CERT = "GoodCACert";

		private const string GOOD_CA_CRL = "GoodCACRL";

		private const string TRUST_ANCHOR_ROOT_CRL = "TrustAnchorRootCRL";

		private const string TRUST_ANCHOR_ROOT_CERTIFICATE = "TrustAnchorRootCertificate";

		private static readonly char[] PKCS12_PASSWORD = "password".ToCharArray();

		private static string NIST_TEST_POLICY_1 = "2.16.840.1.101.3.2.1.48.1";
		private static string NIST_TEST_POLICY_2 = "2.16.840.1.101.3.2.1.48.2";
		private static string NIST_TEST_POLICY_3 = "2.16.840.1.101.3.2.1.48.3";

		private static Map certs = new HashMap();
		private static Map crls = new HashMap();

		private static Set noPolicies = Collections.EMPTY_SET;
		private static Set nistTestPolicy1 = Collections.singleton(NIST_TEST_POLICY_1);
		private static Set nistTestPolicy2 = Collections.singleton(NIST_TEST_POLICY_2);
		private static Set nistTestPolicy3 = Collections.singleton(NIST_TEST_POLICY_3);
		private static Set nistTestPolicy1And2 = new HashSet(Arrays.asList(new string[] {NIST_TEST_POLICY_1, NIST_TEST_POLICY_2}));

		public virtual void testValidSignaturesTest1()
		{
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"ValidCertificatePathTest1EE", GOOD_CA_CERT}, new string[] {GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL});
		}

		public virtual void testInvalidCASignatureTest2()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"ValidCertificatePathTest1EE", "BadSignedCACert"}, new string[] {"BadSignedCACRL", TRUST_ANCHOR_ROOT_CRL}, 1, "CertPathReviewer.signatureNotVerified", "The certificate signature is invalid. A java.security.SignatureException occurred.");
		}

		public virtual void testInvalidEESignatureTest3()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "InvalidEESignatureTest3EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL}, 0, "CertPathReviewer.signatureNotVerified", "The certificate signature is invalid. A java.security.SignatureException occurred.");
		}

		public virtual void testValidDSASignaturesTest4()
		{
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"DSACACert", "ValidDSASignaturesTest4EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "DSACACRL"});
		}
		/*
		public void testValidDSAParameterInheritanceTest5()
		    throws Exception
		{
		    doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
		            new String[] { "DSACACert", "DSAParametersInheritedCACert", "ValidDSAParameterInheritanceTest5EE" }, 
		            new String[] { TRUST_ANCHOR_ROOT_CRL, "DSACACRL", "DSAParametersInheritedCACRL" });
		}
		*/
		public virtual void testInvalidDSASignaturesTest6()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"DSACACert", "InvalidDSASignatureTest6EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "DSACACRL"}, 0, "CertPathReviewer.signatureNotVerified", "The certificate signature is invalid. A java.security.SignatureException occurred.");
		}

		public virtual void testCANotBeforeDateTest1()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"BadnotBeforeDateCACert", "InvalidCAnotBeforeDateTest1EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "BadnotBeforeDateCACRL"}, 1, "CertPathReviewer.certificateNotYetValid", "Could not validate the certificate. Certificate is not valid until Jan 1, 2047 12:01:00 PM GMT.");
		}

		public virtual void testInvalidEENotBeforeDateTest2()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "InvalidEEnotBeforeDateTest2EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL}, 0, "CertPathReviewer.certificateNotYetValid", "Could not validate the certificate. Certificate is not valid until Jan 1, 2047 12:01:00 PM GMT.");
		}

		public virtual void testValidPre2000UTCNotBeforeDateTest3()
		{
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "Validpre2000UTCnotBeforeDateTest3EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL});
		}

		public virtual void testValidGeneralizedTimeNotBeforeDateTest4()
		{
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "ValidGeneralizedTimenotBeforeDateTest4EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL});
		}

		public virtual void testInvalidCANotAfterDateTest5()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"BadnotAfterDateCACert", "InvalidCAnotAfterDateTest5EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "BadnotAfterDateCACRL"}, 1, "CertPathReviewer.certificateExpired", "Could not validate the certificate. Certificate expired on Jan 1, 2002 12:01:00 PM GMT.");
		}

		public virtual void testInvalidEENotAfterDateTest6()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "InvalidEEnotAfterDateTest6EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL}, 0, "CertPathReviewer.certificateExpired", "Could not validate the certificate. Certificate expired on Jan 1, 2002 12:01:00 PM GMT.");
		}

		public virtual void testInvalidValidPre2000UTCNotAfterDateTest7()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "Invalidpre2000UTCEEnotAfterDateTest7EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL}, 0, "CertPathReviewer.certificateExpired", "Could not validate the certificate. Certificate expired on Jan 1, 1999 12:01:00 PM GMT.");
		}

		public virtual void testInvalidNegativeSerialNumberTest15()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"NegativeSerialNumberCACert", "InvalidNegativeSerialNumberTest15EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "NegativeSerialNumberCACRL"}, 0, "CertPathReviewer.certRevoked", "The certificate was revoked at Apr 19, 2001 2:57:20 PM GMT. Reason: Key Compromise.");
		}

		//
		// 4.8 Certificate Policies
		//
		public virtual void testAllCertificatesSamePolicyTest1()
		{
			string[] certList = new string[] {GOOD_CA_CERT, "ValidCertificatePathTest1EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, noPolicies);

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);

			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "CertPathReviewer.invalidPolicy", "Path processing failed on policy.");

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1And2);
		}

		public virtual void testAllCertificatesNoPoliciesTest2()
		{
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"NoPoliciesCACert", "AllCertificatesNoPoliciesTest2EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "NoPoliciesCACRL"});

			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"NoPoliciesCACert", "AllCertificatesNoPoliciesTest2EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "NoPoliciesCACRL"}, noPolicies, -1, "CertPathReviewer.noValidPolicyTree", "Policy checking failed: no valid policy tree found when one expected.");
		}

		public virtual void testDifferentPoliciesTest3()
		{
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL"});

			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL"}, noPolicies, -1, "CertPathReviewer.noValidPolicyTree", "Policy checking failed: no valid policy tree found when one expected.");

			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL"}, nistTestPolicy1And2, -1, "CertPathReviewer.noValidPolicyTree", "Policy checking failed: no valid policy tree found when one expected.");
		}

		public virtual void testDifferentPoliciesTest4()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "GoodsubCACert", "DifferentPoliciesTest4EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "GoodsubCACRL"}, -1, "CertPathReviewer.noValidPolicyTree", "Policy checking failed: no valid policy tree found when one expected.");
		}

		public virtual void testDifferentPoliciesTest5()
		{
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "PoliciesP2subCA2Cert", "DifferentPoliciesTest5EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCA2CRL"}, -1, "CertPathReviewer.noValidPolicyTree", "Policy checking failed: no valid policy tree found when one expected.");
		}

		public virtual void testOverlappingPoliciesTest6()
		{
			string[] certList = new string[] {"PoliciesP1234CACert", "PoliciesP1234subCAP123Cert", "PoliciesP1234subsubCAP123P12Cert", "OverlappingPoliciesTest6EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP1234CACRL", "PoliciesP1234subCAP123CRL", "PoliciesP1234subsubCAP123P12CRL"};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);

			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "CertPathReviewer.invalidPolicy", "Path processing failed on policy.");
		}

		public virtual void testDifferentPoliciesTest7()
		{
			string[] certList = new string[] {"PoliciesP123CACert", "PoliciesP123subCAP12Cert", "PoliciesP123subsubCAP12P1Cert", "DifferentPoliciesTest7EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL", "PoliciesP123subCAP12CRL", "PoliciesP123subsubCAP12P1CRL"};

			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, -1, "CertPathReviewer.noValidPolicyTree", "Policy checking failed: no valid policy tree found when one expected.");
		}

		public virtual void testDifferentPoliciesTest8()
		{
			string[] certList = new string[] {"PoliciesP12CACert", "PoliciesP12subCAP1Cert", "PoliciesP12subsubCAP1P2Cert", "DifferentPoliciesTest8EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL", "PoliciesP12subCAP1CRL", "PoliciesP12subsubCAP1P2CRL"};

			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, -1, "CertPathReviewer.noValidPolicyTree", "Policy checking failed: no valid policy tree found when one expected.");
		}

		public virtual void testDifferentPoliciesTest9()
		{
			string[] certList = new string[] {"PoliciesP123CACert", "PoliciesP123subCAP12Cert", "PoliciesP123subsubCAP12P2Cert", "PoliciesP123subsubsubCAP12P2P1Cert", "DifferentPoliciesTest9EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL", "PoliciesP123subCAP12CRL", "PoliciesP123subsubCAP2P2CRL", "PoliciesP123subsubsubCAP12P2P1CRL"};

			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, -1, "CertPathReviewer.noValidPolicyTree", "Policy checking failed: no valid policy tree found when one expected.");
		}

		public virtual void testAllCertificatesSamePoliciesTest10()
		{
			string[] certList = new string[] {"PoliciesP12CACert", "AllCertificatesSamePoliciesTest10EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL"};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
		}

		public virtual void testAllCertificatesAnyPolicyTest11()
		{
			string[] certList = new string[] {"anyPolicyCACert", "AllCertificatesanyPolicyTest11EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "anyPolicyCACRL"};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
		}

		public virtual void testDifferentPoliciesTest12()
		{
			string[] certList = new string[] {"PoliciesP3CACert", "DifferentPoliciesTest12EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP3CACRL"};

			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, -1, "CertPathReviewer.noValidPolicyTree", "Policy checking failed: no valid policy tree found when one expected.");
		}

		public virtual void testAllCertificatesSamePoliciesTest13()
		{
			string[] certList = new string[] {"PoliciesP123CACert", "AllCertificatesSamePoliciesTest13EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL"};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy3);
		}

		public virtual void testAnyPolicyTest14()
		{
			string[] certList = new string[] {"anyPolicyCACert", "AnyPolicyTest14EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "anyPolicyCACRL"};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "CertPathReviewer.invalidPolicy", "Path processing failed on policy.");
		}

		public virtual void testUserNoticeQualifierTest15()
		{
			string[] certList = new string[] {"UserNoticeQualifierTest15EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "CertPathReviewer.invalidPolicy", "Path processing failed on policy.");
		}

		public virtual void testUserNoticeQualifierTest16()
		{
			string[] certList = new string[] {GOOD_CA_CERT, "UserNoticeQualifierTest16EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);

			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "CertPathReviewer.invalidPolicy", "Path processing failed on policy.");
		}

		public virtual void testUserNoticeQualifierTest17()
		{
			string[] certList = new string[] {GOOD_CA_CERT, "UserNoticeQualifierTest17EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "CertPathReviewer.invalidPolicy", "Path processing failed on policy.");
		}

		public virtual void testUserNoticeQualifierTest18()
		{
			string[] certList = new string[] {"PoliciesP12CACert", "UserNoticeQualifierTest18EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL"};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
		}

		public virtual void testUserNoticeQualifierTest19()
		{
			string[] certList = new string[] {"UserNoticeQualifierTest19EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL};

			doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "CertPathReviewer.invalidPolicy", "Path processing failed on policy.");
		}

		private void doAcceptingTest(string trustAnchor, string[] certs, string[] crls)
		{
			PKIXCertPathReviewer result = doTest(trustAnchor,certs,crls);
			if (!result.isValidCertPath())
			{
				fail("path rejected when should be accepted");
			}
		}

		private void doAcceptingTest(string trustAnchor, string[] certs, string[] crls, Set policies)
		{
			PKIXCertPathReviewer result = doTest(trustAnchor,certs,crls,policies);
			if (!result.isValidCertPath())
			{
				fail("path rejected when should be accepted");
			}
		}

		private void doErrorTest(string trustAnchor, string[] certs, string[] crls, int index, string messageId, string message)
		{
			PKIXCertPathReviewer result = doTest(trustAnchor, certs, crls);
			if (result.isValidCertPath())
			{
				fail("path accepted when should be rejected");
			}
			else
			{
				ErrorBundle msg = (ErrorBundle) result.getErrors(index).iterator().next();
				assertEquals(messageId,msg.getId());
				assertEquals(message,msg.getText(Locale.ENGLISH,TimeZone.getTimeZone("GMT")));
			}
		}

		private void doErrorTest(string trustAnchor, string[] certs, string[] crls, Set policies, int index, string messageId, string message)
		{
			PKIXCertPathReviewer result = doTest(trustAnchor, certs, crls, policies);
			if (result.isValidCertPath())
			{
				fail("path accepted when should be rejected");
			}
			else
			{
				ErrorBundle msg = (ErrorBundle) result.getErrors(index).iterator().next();
				assertEquals(messageId,msg.getId());
				assertEquals(message,msg.getText(Locale.ENGLISH,TimeZone.getTimeZone("GMT")));
			}
		}

		private PKIXCertPathReviewer doTest(string trustAnchor, string[] certs, string[] crls)
		{
			return doTest(trustAnchor, certs, crls, null);
		}

		private PKIXCertPathReviewer doTest(string trustAnchor, string[] certs, string[] crls, Set policies)
		{
			Set trustedSet = Collections.singleton(getTrustAnchor(trustAnchor));
			List certsAndCrls = new ArrayList();
			X509Certificate endCert = loadCert(certs[certs.Length - 1]);

			for (int i = 0; i != certs.Length - 1; i++)
			{
				certsAndCrls.add(loadCert(certs[i]));
			}

			certsAndCrls.add(endCert);

			CertPath certPath = CertificateFactory.getInstance("X.509","BC").generateCertPath(certsAndCrls);

			for (int i = 0; i != crls.Length; i++)
			{
				certsAndCrls.add(loadCrl(crls[i]));
			}

			CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsAndCrls), "BC");

			//CertPathValidator validator = CertPathValidator.getInstance("PKIX","BC");
			PKIXCertPathReviewer reviewer;
			PKIXParameters @params = new PKIXParameters(trustedSet);

			@params.addCertStore(store);
			@params.setRevocationEnabled(true);
			@params.setDate((new GregorianCalendar(2010, 1, 1)).getTime());

			if (policies != null)
			{
				@params.setExplicitPolicyRequired(true);
				@params.setInitialPolicies(policies);
			}

			reviewer = new PKIXCertPathReviewer(certPath,@params);

			return reviewer;
		}

		private X509Certificate loadCert(string certName)
		{
			X509Certificate cert = (X509Certificate)certs.get(certName);

			if (cert != null)
			{
				return cert;
			}

			try
			{
				InputStream @in = new FileInputStream(getPkitsHome() + "/certs/" + certName + ".crt");

				CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

				cert = (X509Certificate)fact.generateCertificate(@in);

				certs.put(certName, cert);

				return cert;
			}
			catch (Exception e)
			{
				throw new IllegalStateException("exception loading certificate " + certName + ": " + e);
			}
		}

		private X509CRL loadCrl(string crlName)
		{
			X509CRL crl = (X509CRL)certs.get(crlName);

			if (crl != null)
			{
				return crl;
			}

			try
			{
				InputStream @in = new FileInputStream(getPkitsHome() + "/crls/" + crlName + ".crl");

				CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

				crl = (X509CRL)fact.generateCRL(@in);

				crls.put(crlName, crl);

				return crl;
			}
			catch (Exception)
			{
				throw new IllegalStateException("exception loading CRL: " + crlName);
			}
		}

		private TrustAnchor getTrustAnchor(string trustAnchorName)
		{
			X509Certificate cert = loadCert(trustAnchorName);
			byte[] extBytes = cert.getExtensionValue(X509Extension.nameConstraints.getId());

			if (extBytes != null)
			{
				ASN1Primitive extValue = X509ExtensionUtil.fromExtensionValue(extBytes);

				return new TrustAnchor(cert, extValue.getEncoded(ASN1Encoding_Fields.DER));
			}

			return new TrustAnchor(cert, null);
		}

		private string getPkitsHome()
		{
			string dataHome = System.getProperty(TEST_DATA_HOME);

			if (string.ReferenceEquals(dataHome, null))
			{
				throw new IllegalStateException(TEST_DATA_HOME + " property not set");
			}

			return dataHome + "/PKITS";
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public virtual void setUp()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("NIST CertPath Tests");

			suite.addTestSuite(typeof(NistCertPathReviewerTest));

			return suite;
		}
	}

}