namespace org.bouncycastle.jce.provider.test
{
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class MultiCertStoreTest : SimpleTest
	{

		public override void performTest()
		{
			basicTest();
		}

		private void basicTest()
		{
			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

			X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.rootCertBin));
			X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.interCertBin));
			X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.finalCertBin));
			X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.rootCrlBin));
			X509CRL interCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.interCrlBin));

			// Testing CollectionCertStore generation from List
			List list = new ArrayList();
			list.add(rootCert);
			list.add(interCert);
			list.add(finalCert);
			list.add(rootCrl);
			list.add(interCrl);
			CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
			CertStore store1 = CertStore.getInstance("Collection", ccsp, "BC");
			CertStore store2 = CertStore.getInstance("Collection", ccsp, "BC");

			List storeList = new ArrayList();
			storeList.add(store1);
			storeList.add(store2);
			CertStore store = CertStore.getInstance("Multi", new MultiCertStoreParameters(storeList));

			// Searching for rootCert by subjectDN
			X509CertSelector targetConstraints = new X509CertSelector();
			targetConstraints.setSubject(rootCert.getSubjectX500Principal().getName());
			Collection certs = store.getCertificates(targetConstraints);

			if (certs.size() != 2 || !certs.contains(rootCert))
			{
				fail("2 rootCerts not found by subjectDN");
			}

			store = CertStore.getInstance("Multi", new MultiCertStoreParameters(storeList, false));
			certs = store.getCertificates(targetConstraints);

			if (certs.size() != 1 || !certs.contains(rootCert))
			{
				fail("1 rootCert not found by subjectDN");
			}
		}

		public override string getName()
		{
			return "MultiCertStore";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new MultiCertStoreTest());
		}

	}

}