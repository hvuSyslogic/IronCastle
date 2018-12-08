namespace org.bouncycastle.crypto.test
{
	using Grain128Engine = org.bouncycastle.crypto.engines.Grain128Engine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// Grain-128 Test
	/// </summary>
	public class Grain128Test : SimpleTest
	{

		internal string keyStream1 = "f09b7bf7d7f6b5c2de2ffc73ac21397f";
		internal string keyStream2 = "afb5babfa8de896b4b9c6acaf7c4fbfd";

		public override string getName()
		{
			return "Grain-128";
		}

		public override void performTest()
		{
			Grain128Test1(new ParametersWithIV(new KeyParameter(Hex.decode("00000000000000000000000000000000")), Hex.decode("000000000000000000000000")));
			Grain128Test2(new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef123456789abcdef0")), Hex.decode("0123456789abcdef12345678")));
			Grain128Test3(new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef123456789abcdef0")), Hex.decode("0123456789abcdef12345678")));
		}

		private void Grain128Test1(CipherParameters @params)
		{
			StreamCipher grain = new Grain128Engine();
			byte[] @in = new byte[16];
			byte[] @out = new byte[16];

			grain.init(true, @params);

			grain.processBytes(@in, 0, @in.Length, @out, 0);

			if (!areEqual(@out, Hex.decode(keyStream1)))
			{
				mismatch("Keystream 1", keyStream1, @out);
			}

			grain.reset();

			grain.processBytes(@in, 0, @in.Length, @out, 0);

			if (!areEqual(@out, Hex.decode(keyStream1)))
			{
				mismatch("Keystream 1", keyStream1, @out);
			}
		}

		private void Grain128Test2(CipherParameters @params)
		{
			StreamCipher grain = new Grain128Engine();
			byte[] @in = new byte[16];
			byte[] @out = new byte[16];

			grain.init(true, @params);

			grain.processBytes(@in, 0, @in.Length, @out, 0);

			if (!areEqual(@out, Hex.decode(keyStream2)))
			{
				mismatch("Keystream 2", keyStream2, @out);
			}

			grain.reset();

			grain.processBytes(@in, 0, @in.Length, @out, 0);

			if (!areEqual(@out, Hex.decode(keyStream2)))
			{
				mismatch("Keystream 2", keyStream2, @out);
			}
		}

		private void Grain128Test3(CipherParameters @params)
		{
			StreamCipher grain = new Grain128Engine();
			byte[] @in = "Encrypt me!".GetBytes();
			byte[] cipher = new byte[@in.Length];
			byte[] clear = new byte[@in.Length];

			grain.init(true, @params);

			grain.processBytes(@in, 0, @in.Length, cipher, 0);
			grain.reset();
			grain.processBytes(cipher, 0, cipher.Length, clear, 0);

			if (!areEqual(@in, clear))
			{
				mismatch("Test 3", StringHelper.NewString(Hex.encode(@in)), clear);
			}
		}

		private void mismatch(string name, string expected, byte[] found)
		{
			fail("mismatch on " + name, expected, StringHelper.NewString(Hex.encode(found)));
		}

		public static void Main(string[] args)
		{
			runTest(new Grain128Test());
		}
	}

}