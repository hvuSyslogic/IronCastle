namespace org.bouncycastle.crypto.test
{

	using X448Agreement = org.bouncycastle.crypto.agreement.X448Agreement;
	using X448KeyPairGenerator = org.bouncycastle.crypto.generators.X448KeyPairGenerator;
	using X448KeyGenerationParameters = org.bouncycastle.crypto.@params.X448KeyGenerationParameters;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class X448Test : SimpleTest
	{
		private static readonly SecureRandom RANDOM = new SecureRandom();

		public override string getName()
		{
			return "X448";
		}

		public static void Main(string[] args)
		{
			runTest(new X448Test());
		}

		public override void performTest()
		{
			for (int i = 0; i < 10; ++i)
			{
				testAgreement();
			}
		}

		private void testAgreement()
		{
			AsymmetricCipherKeyPairGenerator kpGen = new X448KeyPairGenerator();
			kpGen.init(new X448KeyGenerationParameters(RANDOM));

			AsymmetricCipherKeyPair kpA = kpGen.generateKeyPair();
			AsymmetricCipherKeyPair kpB = kpGen.generateKeyPair();

			X448Agreement agreeA = new X448Agreement();
			agreeA.init(kpA.getPrivate());
			byte[] secretA = new byte[agreeA.getAgreementSize()];
			agreeA.calculateAgreement(kpB.getPublic(), secretA, 0);

			X448Agreement agreeB = new X448Agreement();
			agreeB.init(kpB.getPrivate());
			byte[] secretB = new byte[agreeB.getAgreementSize()];
			agreeB.calculateAgreement(kpA.getPublic(), secretB, 0);

			if (!areEqual(secretA, secretB))
			{
				fail("X448 agreement failed");
			}
		}
	}

}