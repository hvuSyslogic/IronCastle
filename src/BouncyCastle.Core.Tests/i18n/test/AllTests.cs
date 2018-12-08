namespace org.bouncycastle.i18n.test
{
	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using HTMLFilterTest = org.bouncycastle.i18n.filter.test.HTMLFilterTest;
	using SQLFilterTest = org.bouncycastle.i18n.filter.test.SQLFilterTest;

	public class AllTests : TestCase
	{

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("i18n tests");
			suite.addTestSuite(typeof(LocalizedMessageTest));
			suite.addTestSuite(typeof(HTMLFilterTest));
			suite.addTestSuite(typeof(SQLFilterTest));
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