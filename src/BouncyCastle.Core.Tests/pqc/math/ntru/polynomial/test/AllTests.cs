namespace org.bouncycastle.pqc.math.ntru.polynomial.test
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
			TestSuite suite = new TestSuite("NTRU Polynomial Tests");

			suite.addTestSuite(typeof(BigDecimalPolynomialTest));
			suite.addTestSuite(typeof(BigIntPolynomialTest));
			suite.addTestSuite(typeof(IntegerPolynomialTest));
			suite.addTestSuite(typeof(LongPolynomial2Test));
			suite.addTestSuite(typeof(LongPolynomial5Test));
			suite.addTestSuite(typeof(ProductFormPolynomialTest));
			suite.addTestSuite(typeof(SparseTernaryPolynomialTest));

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