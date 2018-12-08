using org.bouncycastle.jce.provider;

namespace org.bouncycastle.jce.provider.test.rsa3
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;

	/// <summary>
	/// Marius Schilder's Bleichenbacher's Forgery Attack Tests
	/// </summary>
	public class RSA3CertTest : TestCase
	{
		public virtual void setUp()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}

		public virtual void testA()
		{
			doTest("self-testcase-A.pem");
		}

		public virtual void testB()
		{
			doTest("self-testcase-B.pem");
		}

		public virtual void testC()
		{
			doTest("self-testcase-C.pem");
		}

		public virtual void testD()
		{
			doTest("self-testcase-D.pem");
		}

		public virtual void testE()
		{
			doTest("self-testcase-E.pem");
		}

		public virtual void testF()
		{
			doTest("self-testcase-F.pem");
		}

		public virtual void testG()
		{
			doTest("self-testcase-G.pem");
		}

		public virtual void testH()
		{
			doTest("self-testcase-H.pem");
		}

		public virtual void testI()
		{
			doTest("self-testcase-I.pem");
		}

		public virtual void testJ()
		{
			doTest("self-testcase-J.pem");
		}

		public virtual void testL()
		{
			doTest("self-testcase-L.pem");
		}

		private void doTest(string certName)
		{
			X509Certificate cert = loadCert(certName);
			byte[] tbs = cert.getTBSCertificate();
			Signature sig = Signature.getInstance(cert.getSigAlgName(), "BC");

			sig.initVerify(cert.getPublicKey());

			sig.update(tbs);

			assertFalse(sig.verify(cert.getSignature()));
		}

		private X509Certificate loadCert(string certName)
		{
			CertificateFactory rd = CertificateFactory.getInstance("X.509", "BC");

			return (X509Certificate)rd.generateCertificate(this.GetType().getResourceAsStream(certName));
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("Bleichenbacher's Forgery Attack Tests");

			suite.addTestSuite(typeof(RSA3CertTest));

			return suite;
		}
	}

}