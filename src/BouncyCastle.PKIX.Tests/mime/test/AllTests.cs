namespace org.bouncycastle.mime.test
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
			TestSuite suite = new TestSuite("MIME tests");

			suite.addTestSuite(typeof(Base64TransferEncodingTest));
			suite.addTestSuite(typeof(MimeParserTest));
			suite.addTestSuite(typeof(MultipartParserTest));
			suite.addTestSuite(typeof(QuotedPrintableTest));
			suite.addTestSuite(typeof(TestBoundaryLimitedInputStream));
			suite.addTestSuite(typeof(TestSMIMEEnveloped));
			suite.addTestSuite(typeof(TestSMIMESigned));
			suite.addTestSuite(typeof(TestSMIMESignEncrypt));

			return new MIMETestSetup(suite);
		}
	}

}