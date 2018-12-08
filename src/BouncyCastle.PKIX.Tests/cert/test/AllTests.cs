using org.bouncycastle.util.test;

using System;

namespace org.bouncycastle.cert.test
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
				new CertTest(),
				new DANETest(),
				new PKCS10Test(),
				new AttrCertSelectorTest(),
				new AttrCertTest(),
				new X509ExtensionUtilsTest(),
				new CertPathLoopTest(),
				new GOST3410_2012CMSTest()
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
			TestSuite suite = new TestSuite("Cert Tests");

			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}

			suite.addTestSuite(typeof(AllTests));
			suite.addTestSuite(typeof(BcAttrCertSelectorTest));
			suite.addTestSuite(typeof(BcAttrCertSelectorTest));
			suite.addTestSuite(typeof(BcAttrCertTest));
			suite.addTestSuite(typeof(BcCertTest));
			suite.addTestSuite(typeof(BcPKCS10Test));
			suite.addTest(ConverterTest.suite());

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