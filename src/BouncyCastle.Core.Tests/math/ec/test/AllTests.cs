namespace org.bouncycastle.math.ec.test
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
			TestSuite suite = new TestSuite("EC Math tests");

			suite.addTestSuite(typeof(ECAlgorithmsTest));
			suite.addTestSuite(typeof(ECPointTest));
			suite.addTestSuite(typeof(FixedPointTest));

			return new BCTestSetup(suite);
		}

		internal static List enumToList(Enumeration en)
		{
			List rv = new ArrayList();

			while (en.hasMoreElements())
			{
				rv.add(en.nextElement());
			}

			return rv;
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