namespace org.bouncycastle.crypto.test
{

	using SipHash = org.bouncycastle.crypto.macs.SipHash;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Pack = org.bouncycastle.util.Pack;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/*
	 * SipHash test values from "SipHash: a fast short-input PRF", by Jean-Philippe
	 * Aumasson and Daniel J. Bernstein (https://131002.net/siphash/siphash.pdf), Appendix A.
	 */
	public class SipHashTest : SimpleTest
	{
		private const int UPDATE_BYTES = 0;
		private const int UPDATE_FULL = 1;
		private const int UPDATE_MIX = 2;

		public override string getName()
		{
			return "SipHash";
		}

		public override void performTest()
		{
			byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
			byte[] input = Hex.decode("000102030405060708090a0b0c0d0e");

			runMAC(key, input, UPDATE_BYTES);
			runMAC(key, input, UPDATE_FULL);
			runMAC(key, input, UPDATE_MIX);

			SecureRandom random = new SecureRandom();
			for (int i = 0; i < 100; ++i)
			{
				randomTest(random);
			}
		}

		private void runMAC(byte[] key, byte[] input, int updateType)
		{
			long expected = unchecked((long)0xa129ca6149be45e5L);

			SipHash mac = new SipHash();
			mac.init(new KeyParameter(key));

			updateMAC(mac, input, updateType);

			long result = mac.doFinal();
			if (expected != result)
			{
				fail("Result does not match expected value for doFinal()");
			}

			byte[] expectedBytes = new byte[8];
			Pack.longToLittleEndian(expected, expectedBytes, 0);

			updateMAC(mac, input, updateType);

			byte[] output = new byte[mac.getMacSize()];
			int len = mac.doFinal(output, 0);
			if (len != output.Length)
			{
				fail("Result length does not equal getMacSize() for doFinal(byte[],int)");
			}
			if (!areEqual(expectedBytes, output))
			{
				fail("Result does not match expected value for doFinal(byte[],int)");
			}
		}

		private void randomTest(SecureRandom random)
		{
			byte[] key = new byte[16];
			random.nextBytes(key);

			int length = 1 + RNGUtils.nextInt(random, 1024);
			byte[] input = new byte[length];
			random.nextBytes(input);

			SipHash mac = new SipHash();
			mac.init(new KeyParameter(key));

			updateMAC(mac, input, UPDATE_BYTES);
			long result1 = mac.doFinal();

			updateMAC(mac, input, UPDATE_FULL);
			long result2 = mac.doFinal();

			updateMAC(mac, input, UPDATE_MIX);
			long result3 = mac.doFinal();

			if (result1 != result2 || result1 != result3)
			{
				fail("Inconsistent results in random test");
			}
		}

		private void updateMAC(SipHash mac, byte[] input, int updateType)
		{
			switch (updateType)
			{
			case UPDATE_BYTES:
			{
				for (int i = 0; i < input.Length; ++i)
				{
					mac.update(input[i]);
				}
				break;
			}
			case UPDATE_FULL:
			{
				mac.update(input, 0, input.Length);
				break;
			}
			case UPDATE_MIX:
			{
				int step = Math.Max(1, input.Length / 3);
				int pos = 0;
				while (pos < input.Length)
				{
					mac.update(input[pos++]);
					int len = Math.Min(input.Length - pos, step);
					mac.update(input, pos, len);
					pos += len;
				}
				break;
			}
			default:
				throw new IllegalStateException();
			}
		}

		public static void Main(string[] args)
		{
			runTest(new SipHashTest());
		}
	}

}