namespace org.bouncycastle.crypto.prng.test
{
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class FixedSecureRandomTest : SimpleTest
	{
		internal byte[] @base = Hex.decode("deadbeefdeadbeef");
		internal byte[] r1 = Hex.decode("cafebabecafebabe");
		internal byte[] r2 = Hex.decode("ffffffffcafebabedeadbeef");

		public override string getName()
		{
			return "FixedSecureRandom";
		}

		public override void performTest()
		{
			FixedSecureRandom @fixed = new FixedSecureRandom(@base);
			byte[] buf = new byte[8];

			@fixed.nextBytes(buf);

			if (!Arrays.areEqual(buf, @base))
			{
				fail("wrong data returned");
			}

			@fixed = new FixedSecureRandom(@base);

			byte[] seed = @fixed.generateSeed(8);

			if (!Arrays.areEqual(seed, @base))
			{
				fail("wrong seed data returned");
			}

			if (!@fixed.isExhausted())
			{
				fail("not exhausted");
			}

			@fixed = new FixedSecureRandom(new byte[][] {r1, r2});

			seed = @fixed.generateSeed(12);

			if (!Arrays.areEqual(seed, Hex.decode("cafebabecafebabeffffffff")))
			{
				fail("wrong seed data returned - composite");
			}

			@fixed.nextBytes(buf);

			if (!Arrays.areEqual(buf, Hex.decode("cafebabedeadbeef")))
			{
				fail("wrong data returned");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new FixedSecureRandomTest());
		}
	}

}