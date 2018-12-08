namespace org.bouncycastle.pqc.math.ntru.util.test
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
			TestSuite suite = new TestSuite("NTRU ArrayEncoder Tests");

			suite.addTestSuite(typeof(ArrayEncoderTest));

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