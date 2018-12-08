using org.bouncycastle.util.test;

using System;

namespace org.bouncycastle.crypto.test
{
	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;

	public class AllTests : TestCase
	{
		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("Lightweight Crypto Tests");

			suite.addTestSuite(typeof(SimpleTestTest));
			suite.addTestSuite(typeof(GCMReorderTest));

			return new BCTestSetup(suite);
		}

		public class SimpleTestTest : TestCase
		{
			public virtual void testCrypto()
			{
				Test[] tests = RegressionTest.tests;

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