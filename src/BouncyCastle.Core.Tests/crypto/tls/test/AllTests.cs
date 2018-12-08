namespace org.bouncycastle.crypto.tls.test
{
	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;

	public class AllTests : TestCase
	{
		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("TLS tests");

			suite.addTestSuite(typeof(BasicTlsTest));
			suite.addTestSuite(typeof(DTLSProtocolTest));
			suite.addTestSuite(typeof(DTLSTestCase));
			suite.addTestSuite(typeof(TlsProtocolTest));
			suite.addTestSuite(typeof(TlsProtocolNonBlockingTest));
			suite.addTestSuite(typeof(TlsPSKProtocolTest));
			suite.addTestSuite(typeof(TlsSRPProtocolTest));
			suite.addTestSuite(typeof(TlsTestCase));
			suite.addTest(TlsTestSuite.suite());

			return new BCTestSetup(suite);
		}

		public class BCTestSetup : TestSetup
		{
			public BCTestSetup(Test test) : base(test)
			{
			}

			public virtual void setUp()
			{

			}

			public virtual void tearDown()
			{

			}
		}
	}

}