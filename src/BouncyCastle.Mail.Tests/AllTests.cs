namespace org.bouncycastle.mail.smime.test
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
			TestSuite suite = new TestSuite("SMIME tests");

			suite.addTestSuite(typeof(NewSMIMESignedTest));
			suite.addTestSuite(typeof(SignedMailValidatorTest));
			suite.addTestSuite(typeof(NewSMIMEEnvelopedTest));
			suite.addTestSuite(typeof(SMIMECompressedTest));
			suite.addTestSuite(typeof(SMIMEMiscTest));
			suite.addTestSuite(typeof(SMIMEToolkitTest));

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