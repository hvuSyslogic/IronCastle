using org.bouncycastle.util.test;

using System;

namespace org.bouncycastle.pqc.crypto.test
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
			TestSuite suite = new TestSuite("Lightweight PQ Crypto Tests");

			suite.addTestSuite(typeof(BitStringTest));
			suite.addTestSuite(typeof(EncryptionKeyTest));
			suite.addTestSuite(typeof(NTRUEncryptionParametersTest));
			suite.addTestSuite(typeof(NTRUEncryptTest));
			suite.addTestSuite(typeof(NTRUSignatureParametersTest));
			suite.addTestSuite(typeof(NTRUSignatureKeyTest));
			suite.addTestSuite(typeof(NTRUSignerTest));
			suite.addTestSuite(typeof(NTRUSigningParametersTest));
			suite.addTestSuite(typeof(XMSSMTPrivateKeyTest));
			suite.addTestSuite(typeof(XMSSMTPublicKeyTest));
			suite.addTestSuite(typeof(XMSSMTSignatureTest));
			suite.addTestSuite(typeof(XMSSMTTest));
			suite.addTestSuite(typeof(XMSSOidTest));
			suite.addTestSuite(typeof(XMSSPrivateKeyTest));
			suite.addTestSuite(typeof(XMSSPublicKeyTest));
			suite.addTestSuite(typeof(XMSSReducedSignatureTest));
			suite.addTestSuite(typeof(XMSSSignatureTest));
			suite.addTestSuite(typeof(XMSSTest));
			suite.addTestSuite(typeof(XMSSUtilTest));
			suite.addTestSuite(typeof(AllTests.SimpleTestTest));

			return new BCTestSetup(suite);
		}

		public class SimpleTestTest : TestCase
		{
			public virtual void testPQC()
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