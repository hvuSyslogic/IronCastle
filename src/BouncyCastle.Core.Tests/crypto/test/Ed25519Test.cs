namespace org.bouncycastle.crypto.test
{

	using Ed25519KeyPairGenerator = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
	using Ed25519KeyGenerationParameters = org.bouncycastle.crypto.@params.Ed25519KeyGenerationParameters;
	using Ed25519PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed25519PrivateKeyParameters;
	using Ed25519PublicKeyParameters = org.bouncycastle.crypto.@params.Ed25519PublicKeyParameters;
	using Ed25519Signer = org.bouncycastle.crypto.signers.Ed25519Signer;
	using Ed25519ctxSigner = org.bouncycastle.crypto.signers.Ed25519ctxSigner;
	using Ed25519phSigner = org.bouncycastle.crypto.signers.Ed25519phSigner;
	using Ed25519 = org.bouncycastle.math.ec.rfc8032.Ed25519;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class Ed25519Test : SimpleTest
	{
		private static readonly SecureRandom RANDOM = new SecureRandom();

		public override string getName()
		{
			return "Ed25519";
		}

		public static void Main(string[] args)
		{
			runTest(new Ed25519Test());
		}

		public override void performTest()
		{
			for (int i = 0; i < 10; ++i)
			{
				testConsistency(Ed25519.Algorithm.Ed25519, null);

				byte[] context = randomContext(RANDOM.nextInt() & 255);
				testConsistency(Ed25519.Algorithm.Ed25519ctx, context);
				testConsistency(Ed25519.Algorithm.Ed25519ph, context);
			}
		}

		private Signer createSigner(int algorithm, byte[] context)
		{
			switch (algorithm)
			{
			case Ed25519.Algorithm.Ed25519:
				return new Ed25519Signer();
			case Ed25519.Algorithm.Ed25519ctx:
				return new Ed25519ctxSigner(context);
			case Ed25519.Algorithm.Ed25519ph:
				return new Ed25519phSigner(context);
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
			Ed25519KeyPairGenerator kpg = new Ed25519KeyPairGenerator();
			kpg.init(new Ed25519KeyGenerationParameters(RANDOM));

			AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
			Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)kp.getPrivate();
			Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters)kp.getPublic();

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
				fail("Ed25519(" + algorithm + ") signature failed to verify");
			}

			signature[((int)((uint)RANDOM.nextInt() >> 1)) % signature.Length] ^= (byte)(1 << (RANDOM.nextInt() & 7));

			verifier.init(false, publicKey);
			verifier.update(msg, 0, msg.Length);
			bool shouldNotVerify = verifier.verifySignature(signature);

			if (shouldNotVerify)
			{
				fail("Ed25519(" + algorithm + ") bad signature incorrectly verified");
			}
		}
	}

}