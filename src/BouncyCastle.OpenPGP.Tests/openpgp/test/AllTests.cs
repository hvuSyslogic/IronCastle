using org.bouncycastle.util.test;

namespace org.bouncycastle.openpgp.test
{

	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;

	public class AllTests : TestCase
	{
		public virtual void testPGP()
		{
			Security.addProvider(new BouncyCastleProvider());

			Test[] tests = RegressionTest.tests;

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
			TestSuite suite = new TestSuite("OpenPGP Tests");

			suite.addTestSuite(typeof(AllTests));
			suite.addTestSuite(typeof(DSA2Test));
			suite.addTestSuite(typeof(PGPUnicodeTest));

			return new BCTestSetup(suite);
		}

		public class BCTestSetup : TestSetup
		{
			public BCTestSetup(Test test) : base(test)
			{
			}

			public virtual void setUp()
			{
				Security.addProvider(new BouncyCastleProvider());
			}

			public virtual void tearDown()
			{
				Security.removeProvider("BC");
			}
		}
	}

}