using org.bouncycastle.util.test;

using System;

namespace org.bouncycastle.cert.path.test
{

	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;

	public class AllTests : TestCase
	{
		public virtual void testSimpleTests()
		{
			Test[] tests = new Test[]
			{
				new CertPathTest(),
				new CertPathValidationTest()
			};

			for (int i = 0; i != tests.Length; i++)
			{
				SimpleTestResult result = (SimpleTestResult)tests[i].perform();

				if (!result.isSuccessful())
				{
					if (result.getException() != null)
					{
						Console.WriteLine(result.getException().ToString());
						Console.Write(result.getException().StackTrace);
					}
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
			TestSuite suite = new TestSuite("Cert Path Tests");

			suite.addTestSuite(typeof(AllTests));

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