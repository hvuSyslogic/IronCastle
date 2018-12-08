namespace org.bouncycastle.crypto.test
{

	using Ed448KeyPairGenerator = org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
	using Ed448KeyGenerationParameters = org.bouncycastle.crypto.@params.Ed448KeyGenerationParameters;
	using Ed448PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed448PrivateKeyParameters;
	using Ed448PublicKeyParameters = org.bouncycastle.crypto.@params.Ed448PublicKeyParameters;
	using Ed448Signer = org.bouncycastle.crypto.signers.Ed448Signer;
	using Ed448phSigner = org.bouncycastle.crypto.signers.Ed448phSigner;
	using Ed448 = org.bouncycastle.math.ec.rfc8032.Ed448;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class Ed448Test : SimpleTest
	{
		private static readonly SecureRandom RANDOM = new SecureRandom();

		public override string getName()
		{
			return "Ed448";
		}

		public static void Main(string[] args)
		{
			runTest(new Ed448Test());
		}

		public override void performTest()
		{
			for (int i = 0; i < 10; ++i)
			{
				byte[] context = randomContext(RANDOM.nextInt() & 255);
				testConsistency(Ed448.Algorithm.Ed448, context);
				testConsistency(Ed448.Algorithm.Ed448ph, context);
			}
		}

		private Signer createSigner(int algorithm, byte[] context)
		{
			switch (algorithm)
			{
			case Ed448.Algorithm.Ed448:
				return new Ed448Signer(context);
			case Ed448.Algorithm.Ed448ph:
				return new Ed448phSigner(context);
			default:
				throw new IllegalArgumentException("algorithm");
			}
		}

		private byte[] randomContext(int length)
		{
			byte[] context = new byte[length];
			RANDOM.nextBytes(context);
			return context;
		}

		private void testConsistency(int algorithm, byte[] context)
		{
			Ed448KeyPairGenerator kpg = new Ed448KeyPairGenerator();
			kpg.init(new Ed448KeyGenerationParameters(RANDOM));

			AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
			Ed448PrivateKeyParameters privateKey = (Ed448PrivateKeyParameters)kp.getPrivate();
			Ed448PublicKeyParameters publicKey = (Ed448PublicKeyParameters)kp.getPublic();

			byte[] msg = new byte[RANDOM.nextInt() & 255];
			RANDOM.nextBytes(msg);

			Signer signer = createSigner(algorithm, context);
			signer.init(true, privateKey);
			signer.update(msg, 0, msg.Length);
			byte[] signature = signer.generateSignature();

			Signer verifier = createSigner(algorithm, context);
			verifier.init(false, publicKey);
			verifier.update(msg, 0, msg.Length);
			bool shouldVerify = verifier.verifySignature(signature);

			if (!shouldVerify)
			{
				fail("Ed448(" + algorithm + ") signature failed to verify");
			}

			signature[((int)((uint)RANDOM.nextInt() >> 1)) % signature.Length] ^= (byte)(1 << (RANDOM.nextInt() & 7));

			verifier.init(false, publicKey);
			verifier.update(msg, 0, msg.Length);
			bool shouldNotVerify = verifier.verifySignature(signature);

			if (shouldNotVerify)
			{
				fail("Ed448(" + algorithm + ") bad signature incorrectly verified");
			}
		}
	}

}