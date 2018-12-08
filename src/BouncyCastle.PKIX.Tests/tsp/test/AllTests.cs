using org.bouncycastle.jce.provider;

namespace org.bouncycastle.tsp.test
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
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("TSP Tests");

			suite.addTestSuite(typeof(ParseTest));
			suite.addTestSuite(typeof(NewTSPTest));
			suite.addTestSuite(typeof(CMSTimeStampedDataTest));
			suite.addTestSuite(typeof(CMSTimeStampedDataParserTest));
			suite.addTestSuite(typeof(CMSTimeStampedDataGeneratorTest));
			suite.addTestSuite(typeof(GenTimeAccuracyUnitTest));
			suite.addTestSuite(typeof(TimeStampTokenInfoUnitTest));

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