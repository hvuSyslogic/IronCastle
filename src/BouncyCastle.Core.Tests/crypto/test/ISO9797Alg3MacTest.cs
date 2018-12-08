namespace org.bouncycastle.crypto.test
{
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using ISO9797Alg3Mac = org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
	using ISO7816d4Padding = org.bouncycastle.crypto.paddings.ISO7816d4Padding;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class ISO9797Alg3MacTest : SimpleTest
	{
		internal static byte[] keyBytes = Hex.decode("7CA110454A1A6E570131D9619DC1376E");

		internal static byte[] input1 = "Hello World !!!!".getBytes();

		internal static byte[] output1 = Hex.decode("F09B856213BAB83B");

		public ISO9797Alg3MacTest()
		{
		}

		public override void performTest()
		{
			KeyParameter key = new KeyParameter(keyBytes);
			BlockCipher cipher = new DESEngine();
			Mac mac = new ISO9797Alg3Mac(cipher);

			//
			// standard DAC - zero IV
			//
			mac.init(key);

			mac.update(input1, 0, input1.Length);

			byte[] @out = new byte[8];

			mac.doFinal(@out, 0);

			if (!areEqual(@out, output1))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output1)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			//  reset
			//
			mac.reset();

			mac.init(key);

			for (int i = 0; i != input1.Length / 2; i++)
			{
				mac.update(input1[i]);
			}

			mac.update(input1, input1.Length / 2, input1.Length - (input1.Length / 2));

			mac.doFinal(@out, 0);

			if (!areEqual(@out, output1))
			{
				fail("Reset failed - expected " + StringHelper.NewString(Hex.encode(output1)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			testMacWithIv();
		}

		private void testMacWithIv()
		{
			byte[] inputData = new byte[]{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
			byte[] key = new byte[]{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
			byte[] zeroIv = new byte[8];
			byte[] nonZeroIv = new byte[]{0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4};

			KeyParameter simpleParameter = new KeyParameter(key);
			ParametersWithIV zeroIvParameter = new ParametersWithIV(new KeyParameter(key), zeroIv);

			ISO9797Alg3Mac mac1 = new ISO9797Alg3Mac(new DESEngine(), new ISO7816d4Padding());

			// we calculate a reference MAC with a null IV
			mac1.init(simpleParameter);
			mac1.update(inputData, 0, inputData.Length);
			byte[] output1 = new byte[mac1.getMacSize()];
			mac1.doFinal(output1, 0);

			// we then check that passing a vector of 0s is the same as not using any IV
			ISO9797Alg3Mac mac2 = new ISO9797Alg3Mac(new DESEngine(), new ISO7816d4Padding());
			mac2.init(zeroIvParameter);
			mac2.update(inputData, 0, inputData.Length);
			byte[] output2 = new byte[mac2.getMacSize()];
			mac2.doFinal(output2, 0);
			if (!Arrays.areEqual(output1, output2))
			{
				fail("zero IV test failed");
			}

			// and then check that a non zero IV parameter produces a different results.
			ParametersWithIV nonZeroIvParameter = new ParametersWithIV(new KeyParameter(key), nonZeroIv);
			mac2 = new ISO9797Alg3Mac(new DESEngine(), new ISO7816d4Padding());
			mac2.init(nonZeroIvParameter);
			mac2.update(inputData, 0, inputData.Length);
			output2 = new byte[mac2.getMacSize()];
			mac2.doFinal(output2, 0);
			if (Arrays.areEqual(output1, output2))
			{
				fail("non-zero IV test failed");
			}
		}

		public override string getName()
		{
			return "ISO9797Alg3Mac";
		}

		public static void Main(string[] args)
		{
			runTest(new ISO9797Alg3MacTest());
		}
	}


}