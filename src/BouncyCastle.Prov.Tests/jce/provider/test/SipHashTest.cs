namespace org.bouncycastle.jce.provider.test
{


	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class SipHashTest : SimpleTest
	{
		public override void performTest()
		{
			testMac();
			testKeyGenerator();
		}

		private void testKeyGenerator()
		{
			testKeyGen("SipHash");
			testKeyGen("SipHash-2-4");
			testKeyGen("SipHash-4-8");
		}

		private void testKeyGen(string algorithm)
		{
			KeyGenerator kg = KeyGenerator.getInstance(algorithm, "BC");

			SecretKey key = kg.generateKey();

			if (!key.getAlgorithm().equalsIgnoreCase("SipHash"))
			{
				fail("Unexpected algorithm name in key", "SipHash", key.getAlgorithm());
			}
			if (key.getEncoded().length != 16)
			{
				fail("Expected 128 bit key");
			}
		}

		private void testMac()
		{
			byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
			byte[] input = Hex.decode("000102030405060708090a0b0c0d0e");

			byte[] expected = Hex.decode("e545be4961ca29a1");

			Mac mac = Mac.getInstance("SipHash", "BC");

			mac.init(new SecretKeySpec(key, "SipHash"));

			mac.update(input, 0, input.Length);

			byte[] result = mac.doFinal();

			if (!Arrays.areEqual(expected, result))
			{
				fail("Result does not match expected value for doFinal()");
			}

			mac.init(new SecretKeySpec(key, "SipHash-2-4"));

			mac.update(input, 0, input.Length);

			result = mac.doFinal();
			if (!Arrays.areEqual(expected, result))
			{
				fail("Result does not match expected value for second doFinal()");
			}

			mac = Mac.getInstance("SipHash-2-4", "BC");

			mac.init(new SecretKeySpec(key, "SipHash-2-4"));

			mac.update(input, 0, input.Length);

			result = mac.doFinal();
			if (!Arrays.areEqual(expected, result))
			{
				fail("Result does not match expected value for alias");
			}

			// SipHash 4-8
			expected = Hex.decode("e0a6a97dd589d383");

			mac = Mac.getInstance("SipHash-4-8", "BC");

			mac.init(new SecretKeySpec(key, "SipHash"));

			mac.update(input, 0, input.Length);

			result = mac.doFinal();

			if (!Arrays.areEqual(expected, result))
			{
				fail("Result does not match expected value for SipHash 4-8");
			}
		}

		public override string getName()
		{
			return "SipHash";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new SipHashTest());
		}
	}

}