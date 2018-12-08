using org.bouncycastle.util.test;

namespace org.bouncycastle.cert.ocsp.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;

	public class AllTests : TestCase
	{
		public virtual void testOCSP()
		{
			Security.addProvider(new BouncyCastleProvider());

			Test[] tests = new Test[] {new OCSPTest()};

			for (int i = 0; i != tests.Length; i++)
			{
				SimpleTestResult result = (SimpleTestResult)tests[i].perform();

				if (!result.isSuccessful())
				{
					fail(result.ToString());
				}
			}
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("OCSP Tests");

			suite.addTestSuite(typeof(AllTests));

			return suite;
		}
	}

}