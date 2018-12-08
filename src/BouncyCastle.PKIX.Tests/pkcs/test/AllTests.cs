namespace org.bouncycastle.pkcs.test
{
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
			TestSuite suite = new TestSuite("PKCS Tests");

			suite.addTestSuite(typeof(PfxPduTest));
			suite.addTestSuite(typeof(PKCS10Test));
			suite.addTestSuite(typeof(PKCS8Test));

			return new BCTestSetup(suite);
		}
	}

}