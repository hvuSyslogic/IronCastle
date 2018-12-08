namespace org.bouncycastle.crypto.test
{
	using AESEngine = org.bouncycastle.crypto.engines.AESEngine;
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using SkipjackEngine = org.bouncycastle.crypto.engines.SkipjackEngine;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using CTSBlockCipher = org.bouncycastle.crypto.modes.CTSBlockCipher;
	using OldCTSBlockCipher = org.bouncycastle.crypto.modes.OldCTSBlockCipher;
	using SICBlockCipher = org.bouncycastle.crypto.modes.SICBlockCipher;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// CTS tester
	/// </summary>
	public class CTSTest : SimpleTest
	{
		internal static byte[] in1 = Hex.decode("4e6f7720697320746865207420");
		internal static byte[] in2 = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f0aaa");
		internal static byte[] out1 = Hex.decode("9952f131588465033fa40e8a98");
		internal static byte[] out2 = Hex.decode("358f84d01eb42988dc34efb994");
		internal static byte[] out3 = Hex.decode("170171cfad3f04530c509b0c1f0be0aefbd45a8e3755a873bff5ea198504b71683c6");

		private void testCTS(int id, BlockCipher cipher, CipherParameters @params, byte[] input, byte[] output)
		{
			byte[] @out = new byte[input.Length];
			BufferedBlockCipher engine = new CTSBlockCipher(cipher);

			engine.init(true, @params);

			int len = engine.processBytes(input, 0, input.Length, @out, 0);

			engine.doFinal(@out, len);

			if (!areEqual(output, @out))
			{
				fail("failed encryption expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			engine.init(false, @params);

			len = engine.processBytes(output, 0, output.Length, @out, 0);

			engine.doFinal(@out, len);

			if (!areEqual(input, @out))
			{
				fail("failed decryption expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}
		}

		private void testOldCTS(int id, BlockCipher cipher, CipherParameters @params, byte[] input, byte[] output)
		{
			byte[] @out = new byte[input.Length];
			BufferedBlockCipher engine = new OldCTSBlockCipher(cipher);

			engine.init(true, @params);

			int len = engine.processBytes(input, 0, input.Length, @out, 0);

			engine.doFinal(@out, len);

			if (!areEqual(output, @out))
			{
				fail("failed encryption expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			engine.init(false, @params);

			len = engine.processBytes(output, 0, output.Length, @out, 0);

			engine.doFinal(@out, len);

			if (!areEqual(input, @out))
			{
				fail("failed decryption expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}
		}

		private void testExceptions()
		{
			BufferedBlockCipher engine = new CTSBlockCipher(new DESEngine());
			CipherParameters @params = new KeyParameter(new byte[engine.getBlockSize()]);
			engine.init(true, @params);

			byte[] @out = new byte[engine.getOutputSize(engine.getBlockSize())];

			engine.processBytes(new byte[engine.getBlockSize() - 1], 0, engine.getBlockSize() - 1, @out, 0);
			try
			{
				engine.doFinal(@out, 0);
				fail("Expected CTS encrypt error on < 1 block input");
			}
			catch (DataLengthException)
			{
				// Expected
			}

			engine.init(true, @params);
			engine.processBytes(new byte[engine.getBlockSize()], 0, engine.getBlockSize(), @out, 0);
			try
			{
				engine.doFinal(@out, 0);
			}
			catch (DataLengthException)
			{
				fail("Unexpected CTS encrypt error on == 1 block input");
			}

			engine.init(false, @params);
			engine.processBytes(new byte[engine.getBlockSize() - 1], 0, engine.getBlockSize() - 1, @out, 0);
			try
			{
				engine.doFinal(@out, 0);
				fail("Expected CTS decrypt error on < 1 block input");
			}
			catch (DataLengthException)
			{
				// Expected
			}

			engine.init(false, @params);
			engine.processBytes(new byte[engine.getBlockSize()], 0, engine.getBlockSize(), @out, 0);
			try
			{
				engine.doFinal(@out, 0);
			}
			catch (DataLengthException)
			{
				fail("Unexpected CTS decrypt error on == 1 block input");
			}

			try
			{
				new CTSBlockCipher(new SICBlockCipher(new AESEngine()));
				fail("Expected CTS construction error - only ECB/CBC supported.");
			}
			catch (IllegalArgumentException)
			{
				// Expected
			}

		}

		public override string getName()
		{
			return "CTS";
		}

		public override void performTest()
		{
			byte[] key1 = new byte[] {(byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, unchecked((byte)0x89), unchecked((byte)0xAB), unchecked((byte)0xCD), unchecked((byte)0xEF)};
			byte[] key2 = new byte[] {(byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, unchecked((byte)0x89), unchecked((byte)0xAB), unchecked((byte)0xCD), unchecked((byte)0xEF), unchecked((byte)0xee), unchecked((byte)0xff)};
			byte[] iv = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};

			testCTS(1, new DESEngine(), new KeyParameter(key1), in1, out1);
			testCTS(2, new CBCBlockCipher(new DESEngine()), new ParametersWithIV(new KeyParameter(key1), iv), in1, out2);
			testCTS(3, new CBCBlockCipher(new SkipjackEngine()), new ParametersWithIV(new KeyParameter(key2), iv), in2, out3);

			//
			// test vectors from rfc3962
			//
			byte[] aes128 = Hex.decode("636869636b656e207465726979616b69");
			byte[] aesIn1 = Hex.decode("4920776f756c64206c696b652074686520");
			byte[] aesOut1 = Hex.decode("c6353568f2bf8cb4d8a580362da7ff7f97");
			byte[] aesIn2 = Hex.decode("4920776f756c64206c696b65207468652047656e6572616c20476175277320");
			byte[] aesOut2 = Hex.decode("fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5");
			byte[] aesIn3 = Hex.decode("4920776f756c64206c696b65207468652047656e6572616c2047617527732043");
			byte[] aesOut3 = Hex.decode("39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584");

			testCTS(4, new CBCBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(aes128), new byte[16]), aesIn1, aesOut1);
			testCTS(5, new CBCBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(aes128), new byte[16]), aesIn2, aesOut2);
			testCTS(6, new CBCBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(aes128), new byte[16]), aesIn3, aesOut3);

			testOldCTS(4, new CBCBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(aes128), new byte[16]), aesIn1, aesOut1);
			testOldCTS(5, new CBCBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(aes128), new byte[16]), aesIn2, aesOut2);
			testOldCTS(6, new CBCBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(aes128), new byte[16]), aesIn3, aesOut3);

			byte[] aes1Block = Hex.decode("4920776f756c64206c696b6520746865");
			byte[] preErrata = Hex.decode("e7664c13ff28c965b0d2a0e7ec353706"); // CTS style one block
			byte[] pstErrata = Hex.decode("97687268d6ecccc0c07b25e25ecfe584"); // CBC style one block
			byte[] pstErrataNonZeroIV = Hex.decode("571f5108c53fe95ab52df783df933fa3");

			testCTS(7, new CBCBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(aes128), new byte[16]), aes1Block, pstErrata);
			testCTS(8, new CBCBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(aes128), aes1Block), aes1Block, pstErrataNonZeroIV);
			testOldCTS(9, new CBCBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(aes128), new byte[16]), aes1Block, preErrata);

			byte[] aes128b = Hex.decode("aafd12f659cae63489b479e5076ddec2f06cb58faafd12f6");
			byte[] aesIn1b = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f");
			byte[] aesOut1b = Hex.decode("6db2f802d99e1ef0a5940f306079e083cf87f4d8bb9d1abb36cdd9f44ead7d04");

			testCTS(10, new CBCBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(aes128b), Hex.decode("aafd12f659cae63489b479e5076ddec2")), aesIn1b, aesOut1b);

			testExceptions();
		}

		public static void Main(string[] args)
		{
			runTest(new CTSTest());
		}
	}

}