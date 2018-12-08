namespace org.bouncycastle.jce.provider.test
{
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using X509CertificatePair = org.bouncycastle.x509.X509CertificatePair;


	public class X509CertificatePairTest : SimpleTest
	{
		public override void performTest()
		{
			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

			X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.rootCertBin));
			X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.interCertBin));
			X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.finalCertBin));


			X509CertificatePair pair1 = new X509CertificatePair(rootCert, interCert);
			X509CertificatePair pair2 = new X509CertificatePair(rootCert, interCert);
			X509CertificatePair pair3 = new X509CertificatePair(interCert, finalCert);
			X509CertificatePair pair4 = new X509CertificatePair(rootCert, finalCert);
			X509CertificatePair pair5 = new X509CertificatePair(rootCert, null);
			X509CertificatePair pair6 = new X509CertificatePair(rootCert, null);
			X509CertificatePair pair7 = new X509CertificatePair(null, rootCert);
			X509CertificatePair pair8 = new X509CertificatePair(null, rootCert);

			if (!pair1.Equals(pair2))
			{
				fail("pair1 pair2 equality test");
			}

			if (!pair5.Equals(pair6))
			{
				fail("pair1 pair2 equality test");
			}

			if (!pair7.Equals(pair8))
			{
				fail("pair1 pair2 equality test");
			}

			if (pair1.Equals(null))
			{
				fail("pair1 null equality test");
			}

			if (pair1.GetHashCode() != pair2.GetHashCode())
			{
				fail("pair1 pair2 hashCode equality test");
			}

			if (pair1.Equals(pair3))
			{
				fail("pair1 pair3 inequality test");
			}

			if (pair1.Equals(pair4))
			{
				fail("pair1 pair4 inequality test");
			}

			if (pair1.Equals(pair5))
			{
				fail("pair1 pair5 inequality test");
			}

			if (pair1.Equals(pair7))
			{
				fail("pair1 pair7 inequality test");
			}

			if (pair5.Equals(pair1))
			{
				fail("pair5 pair1 inequality test");
			}

			if (pair7.Equals(pair1))
			{
				fail("pair7 pair1 inequality test");
			}

			if (pair1.getForward() != rootCert)
			{
				fail("pair1 forward test");
			}

			if (pair1.getReverse() != interCert)
			{
				fail("pair1 reverse test");
			}

			if (!areEqual(pair1.getEncoded(), pair2.getEncoded()))
			{
				fail("encoding check");
			}

			pair4 = new X509CertificatePair(rootCert, TestUtils.createExceptionCertificate(false));

			try
			{
				pair4.getEncoded();

				fail("no exception on bad getEncoded()");
			}
			catch (CertificateEncodingException)
			{
				// expected
			}

			pair4 = new X509CertificatePair(rootCert, TestUtils.createExceptionCertificate(true));

			try
			{
				pair4.getEncoded();

				fail("no exception on exception getEncoded()");
			}
			catch (CertificateEncodingException)
			{
				// expected
			}
		}

		public override string getName()
		{
			return "X509CertificatePair";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new X509CertificatePairTest());
		}

	}

}