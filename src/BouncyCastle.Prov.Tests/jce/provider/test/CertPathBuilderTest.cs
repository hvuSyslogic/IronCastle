using System;

namespace org.bouncycastle.jce.provider.test
{

	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class CertPathBuilderTest : SimpleTest
	{

		private void baseTest()
		{
			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

				// initialise CertStore
			X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.rootCertBin));
			X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.interCertBin));
			X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.finalCertBin));
			X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.rootCrlBin));
			X509CRL interCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.interCrlBin));
			List list = new ArrayList();
			list.add(rootCert);
			list.add(interCert);
			list.add(finalCert);
			list.add(rootCrl);
			list.add(interCrl);
			CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
			CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
			DateTime validDate = new DateTime(rootCrl.getThisUpdate().getTime() + 60 * 60 * 1000);

				//Searching for rootCert by subjectDN without CRL
			Set trust = new HashSet();
			trust.add(new TrustAnchor(rootCert, null));

			CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX","BC");
			X509CertSelector targetConstraints = new X509CertSelector();
			targetConstraints.setSubject(finalCert.getSubjectX500Principal().getEncoded());
			PKIXBuilderParameters @params = new PKIXBuilderParameters(trust, targetConstraints);
			@params.addCertStore(store);
			@params.setDate(validDate);
			PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) cpb.build(@params);
			CertPath path = result.getCertPath();

			if (path.getCertificates().size() != 2)
			{
				fail("wrong number of certs in baseTest path");
			}
		}

		private void v0Test()
		{
			// create certificates and CRLs
			KeyPair rootPair = TestUtils.generateRSAKeyPair();
			KeyPair interPair = TestUtils.generateRSAKeyPair();
			KeyPair endPair = TestUtils.generateRSAKeyPair();

			X509Certificate rootCert = TestUtils.generateRootCert(rootPair);
			X509Certificate interCert = TestUtils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
			X509Certificate endCert = TestUtils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);

			BigInteger revokedSerialNumber = BigInteger.valueOf(2);
			X509CRL rootCRL = TestUtils.createCRL(rootCert, rootPair.getPrivate(), revokedSerialNumber);
			X509CRL interCRL = TestUtils.createCRL(interCert, interPair.getPrivate(), revokedSerialNumber);

			// create CertStore to support path building
			List list = new ArrayList();

			list.add(rootCert);
			list.add(interCert);
			list.add(endCert);
			list.add(rootCRL);
			list.add(interCRL);

			CollectionCertStoreParameters @params = new CollectionCertStoreParameters(list);
			CertStore store = CertStore.getInstance("Collection", @params);

			// build the path
			CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
			X509CertSelector pathConstraints = new X509CertSelector();

			pathConstraints.setSubject(endCert.getSubjectX500Principal().getEncoded());

			PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

			buildParams.addCertStore(store);
			buildParams.setDate(DateTime.Now);

			PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
			CertPath path = result.getCertPath();

			if (path.getCertificates().size() != 2)
			{
				fail("wrong number of certs in v0Test path");
			}
		}

		public override void performTest()
		{
			baseTest();
			v0Test();
		}

		public override string getName()
		{
			return "CertPathBuilder";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new CertPathBuilderTest());
		}
	}


}