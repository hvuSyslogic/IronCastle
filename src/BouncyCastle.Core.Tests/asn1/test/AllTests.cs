using org.bouncycastle.util.test;

namespace org.bouncycastle.asn1.test
{
	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;

	public class AllTests : TestCase
	{
		public virtual void testASN1()
		{
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
			TestSuite suite = new TestSuite("ASN.1 Tests");

			suite.addTestSuite(typeof(AllTests));
			suite.addTestSuite(typeof(GetInstanceTest));
			suite.addTestSuite(typeof(ASN1SequenceParserTest));
			suite.addTestSuite(typeof(OctetStringTest));
			suite.addTestSuite(typeof(ParseTest));

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