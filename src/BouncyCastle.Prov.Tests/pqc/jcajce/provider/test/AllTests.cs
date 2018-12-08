namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;

	/// <summary>
	/// Full test suite for the BCPQC provider.
	/// </summary>
	public class AllTests : TestCase
	{
		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("PQC JCE Tests");

			if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
			{
				Security.addProvider(new BouncyCastlePQCProvider());
			}

			suite.addTestSuite(typeof(Sphincs256Test));
			suite.addTestSuite(typeof(RainbowSignatureTest));
			suite.addTestSuite(typeof(McElieceFujisakiCipherTest));
			suite.addTestSuite(typeof(McElieceKobaraImaiCipherTest));
			suite.addTestSuite(typeof(McEliecePointchevalCipherTest));
			suite.addTestSuite(typeof(McElieceCipherTest));
			suite.addTestSuite(typeof(McElieceKeyPairGeneratorTest));
			suite.addTestSuite(typeof(McElieceCCA2KeyPairGeneratorTest));
			suite.addTestSuite(typeof(NewHopeTest));
			suite.addTestSuite(typeof(NewHopeKeyPairGeneratorTest));
			suite.addTestSuite(typeof(Sphincs256Test));
			suite.addTestSuite(typeof(Sphincs256KeyPairGeneratorTest));
			suite.addTestSuite(typeof(XMSSTest));
			suite.addTestSuite(typeof(XMSSMTTest));
			suite.addTestSuite(typeof(QTESLATest));

			return new BCTestSetup(suite);
		}

		public class BCTestSetup : TestSetup
		{
			public BCTestSetup(Test test) : base(test)
			{
			}

			public virtual void setUp()
			{
				Security.addProvider(new BouncyCastlePQCProvider());
			}

			public virtual void tearDown()
			{
				Security.removeProvider("BCPQC");
			}
		}
	}

}