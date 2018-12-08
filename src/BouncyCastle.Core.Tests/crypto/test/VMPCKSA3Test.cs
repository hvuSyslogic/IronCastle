namespace org.bouncycastle.crypto.test
{
	using VMPCKSA3Engine = org.bouncycastle.crypto.engines.VMPCKSA3Engine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// VMPC Test
	/// </summary>
	public class VMPCKSA3Test : SimpleTest
	{
		private static readonly byte[] input = new byte[1000000];

		public override string getName()
		{
			return "VMPC-KSA3";
		}

		private void checkByte(byte[] array, int position, byte b)
		{
			if (array[position] != b)
			{
				fail("Fail on position " + position, StringHelper.NewString(Hex.encode(new byte[] {b})), StringHelper.NewString(Hex.encode(new byte[] {array[position]})));
			}
		}

		public override void performTest()
		{
			byte[] key = Hex.decode("9661410AB797D8A9EB767C21172DF6C7");
			byte[] iv = Hex.decode("4B5C2F003E67F39557A8D26F3DA2B155");
			CipherParameters kp = new KeyParameter(key);
			CipherParameters kpwiv = new ParametersWithIV(kp, iv);

			VMPCKSA3Engine engine = new VMPCKSA3Engine();

			try
			{
				engine.init(true, kp);
				fail("init failed to throw expected exception");
			}
			catch (IllegalArgumentException)
			{
				// Expected
			}

			engine.init(true, kpwiv);
			checkEngine(engine);

			engine.reset();
			byte[] output = checkEngine(engine);

			engine.init(false, kpwiv);
			byte[] recovered = new byte[output.Length];
			engine.processBytes(output, 0, output.Length, recovered, 0);

			if (!Arrays.areEqual(input, recovered))
			{
				fail("decrypted bytes differ from original bytes");
			}
		}

		private byte[] checkEngine(VMPCKSA3Engine engine)
		{
			byte[] output = new byte[input.Length];
			engine.processBytes(input, 0, output.Length, output, 0);

			checkByte(output, 0, unchecked((byte) 0xB6));
			checkByte(output, 1, unchecked((byte) 0xEB));
			checkByte(output, 2, unchecked((byte) 0xAE));
			checkByte(output, 3, unchecked((byte) 0xFE));
			checkByte(output, 252, (byte) 0x48);
			checkByte(output, 253, (byte) 0x17);
			checkByte(output, 254, (byte) 0x24);
			checkByte(output, 255, (byte) 0x73);
			checkByte(output, 1020, (byte) 0x1D);
			checkByte(output, 1021, unchecked((byte) 0xAE));
			checkByte(output, 1022, unchecked((byte) 0xC3));
			checkByte(output, 1023, (byte) 0x5A);
			checkByte(output, 102396, (byte) 0x1D);
			checkByte(output, 102397, unchecked((byte) 0xA7));
			checkByte(output, 102398, unchecked((byte) 0xE1));
			checkByte(output, 102399, unchecked((byte) 0xDC));

			return output;
		}

		public static void Main(string[] args)
		{
			runTest(new VMPCKSA3Test());
		}
	}

}