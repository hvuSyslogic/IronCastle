namespace org.bouncycastle.jcajce.provider.test
{

	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	public class AllTests : TestCase
	{
		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("JCAJCE Provider Tests");

			suite.addTestSuite(typeof(ECAlgorithmParametersTest));
			suite.addTestSuite(typeof(PrivateConstructorTest));
			suite.addTestSuite(typeof(RandomTest));
			suite.addTestSuite(typeof(HybridRandomProviderTest));
			suite.addTestSuite(typeof(RFC3211WrapTest));

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