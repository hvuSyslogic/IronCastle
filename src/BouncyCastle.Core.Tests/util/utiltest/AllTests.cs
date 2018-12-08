namespace org.bouncycastle.util.utiltest
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
			TestSuite suite = new TestSuite("util tests");
			suite.addTestSuite(typeof(IPTest));
			suite.addTestSuite(typeof(BigIntegersTest));
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