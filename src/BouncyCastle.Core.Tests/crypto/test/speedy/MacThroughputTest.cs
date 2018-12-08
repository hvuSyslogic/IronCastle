namespace org.bouncycastle.crypto.test.speedy
{

	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using AESFastEngine = org.bouncycastle.crypto.engines.AESFastEngine;
	using NullEngine = org.bouncycastle.crypto.engines.NullEngine;
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using GMac = org.bouncycastle.crypto.macs.GMac;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using Poly1305 = org.bouncycastle.crypto.macs.Poly1305;
	using SipHash = org.bouncycastle.crypto.macs.SipHash;
	using SkeinMac = org.bouncycastle.crypto.macs.SkeinMac;
	using GCMBlockCipher = org.bouncycastle.crypto.modes.GCMBlockCipher;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	/// <summary>
	/// Microbenchmark of MACs on short, medium, long messages, with optional object creation cost.
	/// </summary>
	public class MacThroughputTest
	{

		private const long CLOCK_SPEED = 2400000000L;

		private static readonly SecureRandom RANDOM = new SecureRandom();
		private static Poly1305KeyGenerator kg = new Poly1305KeyGenerator();

		private static readonly byte[] SHORT_MESSAGE = new byte[16];
		private static readonly byte[] MEDIUM_MESSAGE = new byte[256];
		private static readonly byte[] LONG_MESSAGE = new byte[8192];
		static MacThroughputTest()
		{
			RANDOM.nextBytes(SHORT_MESSAGE);
			RANDOM.nextBytes(MEDIUM_MESSAGE);
			RANDOM.nextBytes(LONG_MESSAGE);
			kg.init(new KeyGenerationParameters(RANDOM, 256));
		}

		private const int SHORT_MESSAGE_COUNT = 20000000;
		private const int MEDIUM_MESSAGE_COUNT = 2200000;
		private const int LONG_MESSAGE_COUNT = 80000;


		private static KeyParameter generatePoly1305Key()
		{
			return new KeyParameter(kg.generateKey());
		}

		public static void Main(string[] args)
		{
			testMac(new HMac(new SHA1Digest()), new KeyParameter(generateNonce(20)), 3);
			testMac(new SkeinMac(SkeinMac.SKEIN_512, 128), new KeyParameter(generateNonce(64)), 2);
			testMac(new SipHash(), new KeyParameter(generateNonce(16)), 1);
			testMac(new CMac(new AESFastEngine()), new KeyParameter(generateNonce(16)), 3);
			testMac(new GMac(new GCMBlockCipher(new AESFastEngine())), new ParametersWithIV(new KeyParameter(generateNonce(16)), generateNonce(16)), 5);
			testMac(new Poly1305(new NullEngine(16)), new ParametersWithIV(generatePoly1305Key(), generateNonce(16)), 1);
			testMac(new Poly1305(new AESFastEngine()), new ParametersWithIV(generatePoly1305Key(), generateNonce(16)), 1);
			testMac(new Poly1305Reference(new NullEngine(16)), new ParametersWithIV(generatePoly1305Key(), generateNonce(16)), 1);
		}

		private static byte[] generateNonce(int sizeBytes)
		{
			byte[] nonce = new byte[16];
			RANDOM.nextBytes(nonce);
			return nonce;
		}

		private static void testMac(Mac mac, CipherParameters @params, int rateFactor)
		{
			JavaSystem.@out.println("=========================");

			long total = testRun(mac, @params, false, MEDIUM_MESSAGE, adjust(MEDIUM_MESSAGE_COUNT, rateFactor));
			JavaSystem.@out.printf("%s Warmup 1 run time: %,d ms\n", mac.getAlgorithmName(), total / 1000000);
			total = testRun(mac, @params, false, MEDIUM_MESSAGE, adjust(MEDIUM_MESSAGE_COUNT, rateFactor));
			JavaSystem.@out.printf("%s Warmup 2 run time: %,d ms\n", mac.getAlgorithmName(), total / 1000000);
			System.gc();
			try
			{
				Thread.sleep(1000);
			}
			catch (InterruptedException)
			{
			}

			test("Short", mac, @params, false, SHORT_MESSAGE, adjust(SHORT_MESSAGE_COUNT, rateFactor));
			// test("Short", mac, params, true, SHORT_MESSAGE, adjust(SHORT_MESSAGE_COUNT, rateFactor));
			test("Medium", mac, @params, false, MEDIUM_MESSAGE, adjust(MEDIUM_MESSAGE_COUNT, rateFactor));
			// test("Medium", mac, params, true, MEDIUM_MESSAGE, adjust(MEDIUM_MESSAGE_COUNT,
			// rateFactor));
			test("Long", mac, @params, false, LONG_MESSAGE, adjust(LONG_MESSAGE_COUNT, rateFactor));
			// test("Long", mac, params, true, LONG_MESSAGE, adjust(LONG_MESSAGE_COUNT, rateFactor));
		}

		private static int adjust(int iterationCount, int rateFactor)
		{
			return (int)(iterationCount * (1.0f / rateFactor));
		}

		private static void test(string name, Mac mac, CipherParameters @params, bool initPerMessage, byte[] message, int adjustedCount)
		{
			JavaSystem.@out.println("=========================");
			long total = testRun(mac, @params, initPerMessage, message, adjustedCount);

			long averageRuntime = total / adjustedCount;
			JavaSystem.@out.printf("%s %-7s%s Total run time:   %,d ms\n", mac.getAlgorithmName(), name, initPerMessage ? "*" : " ", total / 1000000);
			JavaSystem.@out.printf("%s %-7s%s Average run time: %,d ns\n", mac.getAlgorithmName(), name, initPerMessage ? "*" : " ", averageRuntime);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final long mbPerSecond = (long)((double)message.length / averageRuntime * 1000000000 / (1024 * 1024));
			long mbPerSecond = (long)((double)message.Length / averageRuntime * 1000000000 / (1024 * 1024));
			JavaSystem.@out.printf("%s %-7s%s Average speed:    %,d MB/s\n", mac.getAlgorithmName(), name, initPerMessage ? "*" : " ", mbPerSecond);
			JavaSystem.@out.printf("%s %-7s%s Average speed:    %,f c/b\n", mac.getAlgorithmName(), name, initPerMessage ? "*" : " ", CLOCK_SPEED / (double)(mbPerSecond * (1024 * 1024)));
		}

		private static long testRun(Mac mac, CipherParameters @params, bool initPerMessage, byte[] message, int adjustedCount)
		{
			byte[] @out = new byte[mac.getMacSize()];

			if (!initPerMessage)
			{
				mac.init(@params);
			}
			long start = System.nanoTime();

			for (int i = 0; i < adjustedCount; i++)
			{
				if (initPerMessage)
				{
					mac.init(@params);
				}
				mac.update(message, 0, message.Length);
				mac.doFinal(@out, 0);
			}
			long total = System.nanoTime() - start;
			return total;
		}
	}

}