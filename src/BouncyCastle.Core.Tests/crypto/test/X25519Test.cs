namespace org.bouncycastle.crypto.test
{

	using X25519Agreement = org.bouncycastle.crypto.agreement.X25519Agreement;
	using X25519KeyPairGenerator = org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
	using X25519KeyGenerationParameters = org.bouncycastle.crypto.@params.X25519KeyGenerationParameters;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class X25519Test : SimpleTest
	{
		private static readonly SecureRandom RANDOM = new SecureRandom();

		public override string getName()
		{
			return "X25519";
		}

		public static void Main(string[] args)
		{
			runTest(new X25519Test());
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
			AsymmetricCipherKeyPairGenerator kpGen = new X25519KeyPairGenerator();
			kpGen.init(new X25519KeyGenerationParameters(RANDOM));

			AsymmetricCipherKeyPair kpA = kpGen.generateKeyPair();
			AsymmetricCipherKeyPair kpB = kpGen.generateKeyPair();

			X25519Agreement agreeA = new X25519Agreement();
			agreeA.init(kpA.getPrivate());
			byte[] secretA = new byte[agreeA.getAgreementSize()];
			agreeA.calculateAgreement(kpB.getPublic(), secretA, 0);

			X25519Agreement agreeB = new X25519Agreement();
			agreeB.init(kpB.getPrivate());
			byte[] secretB = new byte[agreeB.getAgreementSize()];
			agreeB.calculateAgreement(kpA.getPublic(), secretB, 0);

			if (!areEqual(secretA, secretB))
			{
				fail("X25519 agreement failed");
			}
		}
	}

}