namespace org.bouncycastle.pqc.crypto.test
{


	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using SHA224Digest = org.bouncycastle.crypto.digests.SHA224Digest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using RainbowKeyGenerationParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
	using RainbowKeyPairGenerator = org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
	using RainbowParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
	using RainbowSigner = org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class RainbowSignerTest : SimpleTest
	{
		public override string getName()
		{
			return "Rainbow";
		}

		public override void performTest()
		{
			RainbowParameters @params = new RainbowParameters();

			RainbowKeyPairGenerator rainbowKeyGen = new RainbowKeyPairGenerator();
			RainbowKeyGenerationParameters genParam = new RainbowKeyGenerationParameters(new SecureRandom(), @params);

			rainbowKeyGen.init(genParam);

			AsymmetricCipherKeyPair pair = rainbowKeyGen.generateKeyPair();

			ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), new SecureRandom());

			DigestingMessageSigner rainbowSigner = new DigestingMessageSigner(new RainbowSigner(), new SHA224Digest());

			rainbowSigner.init(true, param);

			byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
			rainbowSigner.update(message, 0, message.Length);
			byte[] sig = rainbowSigner.generateSignature();

			rainbowSigner.init(false, pair.getPublic());
			rainbowSigner.update(message, 0, message.Length);

			if (!rainbowSigner.verifySignature(sig))
			{
				fail("verification fails");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new RainbowSignerTest());
		}
	}

}