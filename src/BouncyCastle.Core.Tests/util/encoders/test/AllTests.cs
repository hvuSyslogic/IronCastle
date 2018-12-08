namespace org.bouncycastle.util.encoders.test
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

			UTF8Test.main(null);
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("encoder tests");
			suite.addTestSuite(typeof(Base64Test));
			suite.addTestSuite(typeof(UrlBase64Test));
			suite.addTestSuite(typeof(HexTest));
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