namespace org.bouncycastle.est.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	public class AllTests : TestCase
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		public virtual void setUp()
		{
			if (Security.getProvider(BC) != null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("EST tests");

			suite.addTestSuite(typeof(ESTParsingTest));
			suite.addTestSuite(typeof(HostNameAuthorizerMatchTest));
			suite.addTestSuite(typeof(TestHostNameAuthorizer));

			return new ESTTestSetup(suite);
		}
	}

}