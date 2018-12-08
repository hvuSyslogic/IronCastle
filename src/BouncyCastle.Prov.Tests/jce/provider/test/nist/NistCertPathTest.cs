using org.bouncycastle.jce.provider;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jce.provider.test.nist
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using Extension = org.bouncycastle.asn1.x509.Extension;

	/// <summary>
	/// NIST CertPath test data for RFC 3280
	/// </summary>
	public class NistCertPathTest : TestCase
	{
		private const string TEST_DATA_HOME = "bc.test.data.home";

		private const string GOOD_CA_CERT = "GoodCACert";

		private const string GOOD_CA_CRL = "GoodCACRL";

		private const string TRUST_ANCHOR_ROOT_CRL = "TrustAnchorRootCRL";

		private const string TRUST_ANCHOR_ROOT_CERTIFICATE = "TrustAnchorRootCertificate";

		private static readonly char[] PKCS12_PASSWORD = "password".ToCharArray();

		private const string ANY_POLICY = "2.5.29.32.0";
		private const string NIST_TEST_POLICY_1 = "2.16.840.1.101.3.2.1.48.1";
		private const string NIST_TEST_POLICY_2 = "2.16.840.1.101.3.2.1.48.2";
		private const string NIST_TEST_POLICY_3 = "2.16.840.1.101.3.2.1.48.3";

		private static Map certs = new HashMap();
		private static Map crls = new HashMap();

		private static Set noPolicies = Collections.EMPTY_SET;
		private static Set anyPolicy = Collections.singleton(ANY_POLICY);
		private static Set nistTestPolicy1 = Collections.singleton(NIST_TEST_POLICY_1);
		private static Set nistTestPolicy2 = Collections.singleton(NIST_TEST_POLICY_2);
		private static Set nistTestPolicy3 = Collections.singleton(NIST_TEST_POLICY_3);
		private static Set nistTestPolicy1And2 = new HashSet(Arrays.asList(new string[] {NIST_TEST_POLICY_1, NIST_TEST_POLICY_2}));

		public virtual void setUp()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}

		public virtual void testValidSignaturesTest1()
		{
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"ValidCertificatePathTest1EE", GOOD_CA_CERT}, new string[] {GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL});
		}

		public virtual void testInvalidCASignatureTest2()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"ValidCertificatePathTest1EE", "BadSignedCACert"}, new string[] {"BadSignedCACRL", TRUST_ANCHOR_ROOT_CRL}, 1, "TrustAnchor found but certificate validation failed.");
		}

		public virtual void testInvalidEESignatureTest3()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "InvalidEESignatureTest3EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL}, 0, "Could not validate certificate signature.");
		}

		public virtual void testValidDSASignaturesTest4()
		{
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"DSACACert", "ValidDSASignaturesTest4EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "DSACACRL"});
		}

		// 4.1.5
		public virtual void testValidDSAParameterInheritanceTest5()
		{
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"DSACACert", "DSAParametersInheritedCACert", "ValidDSAParameterInheritanceTest5EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "DSACACRL", "DSAParametersInheritedCACRL"});
		}

		public virtual void testInvalidDSASignaturesTest6()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"DSACACert", "InvalidDSASignatureTest6EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "DSACACRL"}, 0, "Could not validate certificate signature.");
		}

		public virtual void testCANotBeforeDateTest1()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"BadnotBeforeDateCACert", "InvalidCAnotBeforeDateTest1EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "BadnotBeforeDateCACRL"}, 1, "Could not validate certificate: certificate not valid till 20470101120100GMT+00:00");
		}

		public virtual void testInvalidEENotBeforeDateTest2()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "InvalidEEnotBeforeDateTest2EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL}, 0, "Could not validate certificate: certificate not valid till 20470101120100GMT+00:00");
		}

		public virtual void testValidPre2000UTCNotBeforeDateTest3()
		{
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "Validpre2000UTCnotBeforeDateTest3EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL});
		}

		public virtual void testValidGeneralizedTimeNotBeforeDateTest4()
		{
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "ValidGeneralizedTimenotBeforeDateTest4EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL});
		}

		public virtual void testInvalidCANotAfterDateTest5()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"BadnotAfterDateCACert", "InvalidCAnotAfterDateTest5EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "BadnotAfterDateCACRL"}, 1, "Could not validate certificate: certificate expired on 20020101120100GMT+00:00");
		}

		public virtual void testInvalidEENotAfterDateTest6()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "InvalidEEnotAfterDateTest6EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL}, 0, "Could not validate certificate: certificate expired on 20020101120100GMT+00:00");
		}

		public virtual void testInvalidValidPre2000UTCNotAfterDateTest7()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "Invalidpre2000UTCEEnotAfterDateTest7EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL}, 0, "Could not validate certificate: certificate expired on 19990101120100GMT+00:00");
		}

		public virtual void testInvalidNegativeSerialNumberTest15()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"NegativeSerialNumberCACert", "InvalidNegativeSerialNumberTest15EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "NegativeSerialNumberCACRL"}, 0, "Certificate revocation after 2001-04-19 14:57:20 +0000", "reason: keyCompromise");
		}

		//
		// 4.8 Certificate Policies
		//
		public virtual void testAllCertificatesSamePolicyTest1()
		{
			string[] certList = new string[] {GOOD_CA_CERT, "ValidCertificatePathTest1EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, noPolicies);

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "Path processing failed on policy.");

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1And2);
		}

		public virtual void testAllCertificatesNoPoliciesTest2()
		{
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"NoPoliciesCACert", "AllCertificatesNoPoliciesTest2EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "NoPoliciesCACRL"});

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {"NoPoliciesCACert", "AllCertificatesNoPoliciesTest2EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, "NoPoliciesCACRL"}, noPolicies, 1, "No valid policy tree found when one expected.");
		}

		public virtual void testDifferentPoliciesTest3()
		{
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL"});

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL"}, noPolicies, 1, "No valid policy tree found when one expected.");

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL"}, nistTestPolicy1And2, 1, "No valid policy tree found when one expected.");
		}

		public virtual void testDifferentPoliciesTest4()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "GoodsubCACert", "DifferentPoliciesTest4EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "GoodsubCACRL"}, 0, "No valid policy tree found when one expected.");
		}

		public virtual void testDifferentPoliciesTest5()
		{
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, new string[] {GOOD_CA_CERT, "PoliciesP2subCA2Cert", "DifferentPoliciesTest5EE"}, new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCA2CRL"}, 0, "No valid policy tree found when one expected.");
		}

		public virtual void testOverlappingPoliciesTest6()
		{
			string[] certList = new string[] {"PoliciesP1234CACert", "PoliciesP1234subCAP123Cert", "PoliciesP1234subsubCAP123P12Cert", "OverlappingPoliciesTest6EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP1234CACRL", "PoliciesP1234subCAP123CRL", "PoliciesP1234subsubCAP123P12CRL"};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "Path processing failed on policy.");
		}

		public virtual void testDifferentPoliciesTest7()
		{
			string[] certList = new string[] {"PoliciesP123CACert", "PoliciesP123subCAP12Cert", "PoliciesP123subsubCAP12P1Cert", "DifferentPoliciesTest7EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL", "PoliciesP123subCAP12CRL", "PoliciesP123subsubCAP12P1CRL"};

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, 0, "No valid policy tree found when one expected.");
		}

		public virtual void testDifferentPoliciesTest8()
		{
			string[] certList = new string[] {"PoliciesP12CACert", "PoliciesP12subCAP1Cert", "PoliciesP12subsubCAP1P2Cert", "DifferentPoliciesTest8EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL", "PoliciesP12subCAP1CRL", "PoliciesP12subsubCAP1P2CRL"};

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, 1, "No valid policy tree found when one expected.");
		}

		public virtual void testDifferentPoliciesTest9()
		{
			string[] certList = new string[] {"PoliciesP123CACert", "PoliciesP123subCAP12Cert", "PoliciesP123subsubCAP12P2Cert", "PoliciesP123subsubsubCAP12P2P1Cert", "DifferentPoliciesTest9EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL", "PoliciesP123subCAP12CRL", "PoliciesP123subsubCAP2P2CRL", "PoliciesP123subsubsubCAP12P2P1CRL"};

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, 1, "No valid policy tree found when one expected.");
		}

		public virtual void testAllCertificatesSamePoliciesTest10()
		{
			string[] certList = new string[] {"PoliciesP12CACert", "AllCertificatesSamePoliciesTest10EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL"};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
		}

		public virtual void testAllCertificatesAnyPolicyTest11()
		{
			string[] certList = new string[] {"anyPolicyCACert", "AllCertificatesanyPolicyTest11EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "anyPolicyCACRL"};

			PKIXCertPathValidatorResult result = doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);

			result = doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
		}

		public virtual void testDifferentPoliciesTest12()
		{
			string[] certList = new string[] {"PoliciesP3CACert", "DifferentPoliciesTest12EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP3CACRL"};

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, 0, "No valid policy tree found when one expected.");
		}

		public virtual void testAllCertificatesSamePoliciesTest13()
		{
			string[] certList = new string[] {"PoliciesP123CACert", "AllCertificatesSamePoliciesTest13EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL"};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy3);
		}

		public virtual void testAnyPolicyTest14()
		{
			string[] certList = new string[] {"anyPolicyCACert", "AnyPolicyTest14EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "anyPolicyCACRL"};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "Path processing failed on policy.");
		}

		public virtual void testUserNoticeQualifierTest15()
		{
			string[] certList = new string[] {"UserNoticeQualifierTest15EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "Path processing failed on policy.");
		}

		public virtual void testUserNoticeQualifierTest16()
		{
			string[] certList = new string[] {GOOD_CA_CERT, "UserNoticeQualifierTest16EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL};

			PKIXCertPathValidatorResult result = doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);

			result = doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "Path processing failed on policy.");
		}

		public virtual void testUserNoticeQualifierTest17()
		{
			string[] certList = new string[] {GOOD_CA_CERT, "UserNoticeQualifierTest17EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "Path processing failed on policy.");
		}

		public virtual void testUserNoticeQualifierTest18()
		{
			string[] certList = new string[] {"PoliciesP12CACert", "UserNoticeQualifierTest18EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL"};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
		}

		public virtual void testUserNoticeQualifierTest19()
		{
			string[] certList = new string[] {"UserNoticeQualifierTest19EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2, -1, "Path processing failed on policy.");
		}

		public virtual void testInvalidInhibitPolicyMappingTest1()
		{
			string[] certList = new string[] {"inhibitPolicyMapping0CACert", "inhibitPolicyMapping0subCACert", "InvalidinhibitPolicyMappingTest1EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "inhibitPolicyMapping0CACRL", "inhibitPolicyMapping0subCACRL"};

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null, 0, "No valid policy tree found when one expected.");
		}

		public virtual void testValidinhibitPolicyMappingTest2()
		{
			string[] certList = new string[] {"inhibitPolicyMapping1P12CACert", "inhibitPolicyMapping1P12subCACert", "ValidinhibitPolicyMappingTest2EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "inhibitPolicyMapping1P12CACRL", "inhibitPolicyMapping1P12subCACRL"};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
		}

		// 4.12.7
		public virtual void testValidSelfIssuedinhibitAnyPolicyTest7()
		{
			string[] certList = new string[] {"inhibitAnyPolicy1CACert", "inhibitAnyPolicy1SelfIssuedCACert", "inhibitAnyPolicy1subCA2Cert", "ValidSelfIssuedinhibitAnyPolicyTest7EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "inhibitAnyPolicy1CACRL", "inhibitAnyPolicy1subCA2CRL"};

			doBuilderTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null, false, false);
		}

		// 4.4.19
		public virtual void testValidSeparateCertificateandCRLKeysTest19()
		{
			string[] certList = new string[] {"SeparateCertificateandCRLKeysCertificateSigningCACert", "SeparateCertificateandCRLKeysCRLSigningCert", "ValidSeparateCertificateandCRLKeysTest19EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "SeparateCertificateandCRLKeysCRL"};

			doBuilderTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null, false, false);
		}

		public virtual void testValidpathLenConstraintTest13()
		{
			string[] certList = new string[] {"pathLenConstraint6CACert", "pathLenConstraint6subCA4Cert", "pathLenConstraint6subsubCA41Cert", "pathLenConstraint6subsubsubCA41XCert", "ValidpathLenConstraintTest13EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "pathLenConstraint6CACRL", "pathLenConstraint6subCA4CRL", "pathLenConstraint6subsubCA41CRL", "pathLenConstraint6subsubsubCA41XCRL"};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null);
		}

		// 4.4.10
		public virtual void testInvalidUnknownCRLExtensionTest10()
		{
			string[] certList = new string[] {"UnknownCRLExtensionCACert", "InvalidUnknownCRLExtensionTest10EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "UnknownCRLExtensionCACRL"};

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null, 0, "CRL contains unsupported critical extensions.");

		}

		// 4.14.3
		public virtual void testInvaliddistributionPointTest3()
		{
			string[] certList = new string[] {"distributionPoint1CACert", "InvaliddistributionPointTest3EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "distributionPoint1CACRL"};

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null, 0, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
		}

		// 4.14.5
		public virtual void testValiddistributionPointTest5()
		{
			string[] certList = new string[] {"distributionPoint2CACert", "ValiddistributionPointTest5EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "distributionPoint2CACRL"};

			doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null);
		}


		// 4.14.8
		public virtual void testInvaliddistributionPointTest8()
		{
			string[] certList = new string[] {"distributionPoint2CACert", "InvaliddistributionPointTest8EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "distributionPoint2CACRL"};

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null, 0, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
		}

		// 4.14.9
		public virtual void testInvaliddistributionPointTest9()
		{
			string[] certList = new string[] {"distributionPoint2CACert", "InvaliddistributionPointTest9EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "distributionPoint2CACRL"};

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null, 0, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
		}

		// 4.14.17
		public virtual void testInvalidonlySomeReasonsTest17()
		{
			string[] certList = new string[] {"onlySomeReasonsCA2Cert", "InvalidonlySomeReasonsTest17EE"};
			string[] crlList = new string[] {TRUST_ANCHOR_ROOT_CRL, "onlySomeReasonsCA2CRL1", "onlySomeReasonsCA2CRL2"};

			doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null, 0, "Certificate status could not be determined.");
		}

		// section 4.14: tests 17, 24, 25, 30, 31, 32, 33, 35

		// section 4.15: tests 5, 7
		private void doExceptionTest(string trustAnchor, string[] certs, string[] crls, int index, string message)
		{
			try
			{
				doTest(trustAnchor, certs, crls);

				fail("path accepted when should be rejected");
			}
			catch (CertPathValidatorException e)
			{
				assertEquals(index, e.getIndex());
				assertEquals(message, e.Message);
			}
		}

		private void doExceptionTest(string trustAnchor, string[] certs, string[] crls, Set policies, int index, string message)
		{
			try
			{
				doTest(trustAnchor, certs, crls, policies);

				fail("path accepted when should be rejected");
			}
			catch (CertPathValidatorException e)
			{
				assertEquals(index, e.getIndex());
				assertEquals(message, e.Message);
			}
		}

		private void doExceptionTest(string trustAnchor, string[] certs, string[] crls, int index, string mesStart, string mesEnd)
		{
			try
			{
				doTest(trustAnchor, certs, crls);

				fail("path accepted when should be rejected");
			}
			catch (CertPathValidatorException e)
			{
				assertEquals(index, e.getIndex());
				assertTrue(e.Message.StartsWith(mesStart));
				assertTrue(e.Message.EndsWith(mesEnd));
			}
		}

		private PKIXCertPathValidatorResult doTest(string trustAnchor, string[] certs, string[] crls)
		{
			return doTest(trustAnchor, certs, crls, null);
		}

		private PKIXCertPathValidatorResult doTest(string trustAnchor, string[] certs, string[] crls, Set policies)
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

			CertPathValidator validator = CertPathValidator.getInstance("PKIX","BC");
			PKIXParameters @params = new PKIXParameters(trustedSet);

			@params.addCertStore(store);
			@params.setRevocationEnabled(true);
			@params.setDate((new GregorianCalendar(2010, 1, 1)).getTime());

			if (policies != null)
			{
				@params.setExplicitPolicyRequired(true);
				@params.setInitialPolicies(policies);
			}

			return (PKIXCertPathValidatorResult)validator.validate(certPath, @params);
		}

		private PKIXCertPathBuilderResult doBuilderTest(string trustAnchor, string[] certs, string[] crls, Set initialPolicies, bool policyMappingInhibited, bool anyPolicyInhibited)
		{
			Set trustedSet = Collections.singleton(getTrustAnchor(trustAnchor));
			List certsAndCrls = new ArrayList();
			X509Certificate endCert = loadCert(certs[certs.Length - 1]);

			for (int i = 0; i != certs.Length - 1; i++)
			{
				certsAndCrls.add(loadCert(certs[i]));
			}

			certsAndCrls.add(endCert);

			for (int i = 0; i != crls.Length; i++)
			{
				certsAndCrls.add(loadCrl(crls[i]));
			}

			CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsAndCrls), "BC");

			CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");

			X509CertSelector endSelector = new X509CertSelector();

			endSelector.setCertificate(endCert);

			PKIXBuilderParameters builderParams = new PKIXBuilderParameters(trustedSet, endSelector);

			if (initialPolicies != null)
			{
				builderParams.setInitialPolicies(initialPolicies);
				builderParams.setExplicitPolicyRequired(true);
			}
			if (policyMappingInhibited)
			{
				builderParams.setPolicyMappingInhibited(policyMappingInhibited);
			}
			if (anyPolicyInhibited)
			{
				builderParams.setAnyPolicyInhibited(anyPolicyInhibited);
			}

			builderParams.addCertStore(store);
			builderParams.setDate((new GregorianCalendar(2010, 1, 1)).getTime());

			try
			{
				return (PKIXCertPathBuilderResult)builder.build(builderParams);
			}
			catch (CertPathBuilderException e)
			{
				throw (Exception)e.InnerException;
			}
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
			byte[] extBytes = cert.getExtensionValue(Extension.nameConstraints.getId());

			if (extBytes != null)
			{
				ASN1Encodable extValue = ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extBytes).getOctets());

				return new TrustAnchor(cert, extValue.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER));
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

		public static Test suite()
		{
			TestSuite suite = new TestSuite("NIST CertPath Tests");

			suite.addTestSuite(typeof(NistCertPathTest));

			return suite;
		}
	}

}