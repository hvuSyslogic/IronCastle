namespace org.bouncycastle.crypto.test
{

	using AESWrapPadEngine = org.bouncycastle.crypto.engines.AESWrapPadEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// This is a test harness I use because I cannot modify the BC test harness without
	/// invalidating the signature on their signed provider library. The code here is not
	/// high quality but it does test the RFC vectors as well as randomly generated values.
	/// The RFC test vectors are tested by making sure both the ciphertext and decrypted
	/// values match the expected values whereas the random values are just checked to make
	/// sure that:
	/// <para>unwrap(wrap(random_value, random_kek), random_kek) == random_value.</para>
	/// </summary>

	public class AESWrapPadTest : SimpleTest
	{

		private readonly int numOfRandomIterations = 100;

		public AESWrapPadTest()
		{

		}

		private void wrapAndUnwrap(byte[] kek, byte[] key, byte[] expected)
		{
			Wrapper wrapper = new AESWrapPadEngine();

			wrapper.init(true, new KeyParameter(kek));

			byte[] cipherText = wrapper.wrap(key, 0, key.Length);
			if (!areEqual(cipherText, expected))
			{
				fail("Wrapped value does not match expected.");
			}
			wrapper.init(false, new KeyParameter(kek));
			byte[] plainText = wrapper.unwrap(cipherText, 0, cipherText.Length);

			if (!areEqual(key, plainText))
			{
				fail("Unwrapped value does not match original.");
			}
		}

		private void wrapAndUnwrap(byte[] kek, byte[] key)
		{
			Wrapper wrapper = new AESWrapPadEngine();

			wrapper.init(true, new KeyParameter(kek));

			byte[] cipherText = wrapper.wrap(key, 0, key.Length);

			wrapper.init(false, new KeyParameter(kek));
			byte[] plainText = wrapper.unwrap(cipherText, 0, cipherText.Length);

			if (!areEqual(key, plainText))
			{
				fail("Unwrapped value does not match original.");
			}
		}

		private void wrapWithIVTest()
		{
			byte[] kek = Hex.decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
			byte[] key = Hex.decode("c37b7e6492584340bed12207808941155068f738");
			byte[] expected = Hex.decode("5cbdb3fb71351d0e628b85dbcba1a1890d4db26d1335e11d1aabea11124caad0");

			Wrapper wrapper = new AESWrapPadEngine();

			wrapper.init(true, new ParametersWithIV(new KeyParameter(kek), Hex.decode("33333333")));

			byte[] cipherText = wrapper.wrap(key, 0, key.Length);
			if (!areEqual(cipherText, expected))
			{
				fail("Wrapped value does not match expected.");
			}
			wrapper.init(false, new ParametersWithIV(new KeyParameter(kek), Hex.decode("33333333")));
			byte[] plainText = wrapper.unwrap(cipherText, 0, cipherText.Length);

			if (!areEqual(key, plainText))
			{
				fail("Unwrapped value does not match original.");
			}
		}

		public override string getName()
		{
			return "AESWrapPad";
		}

		public override void performTest()
		{
			// test RFC 5649 test vectors
			byte[] kek = Hex.decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
			byte[] key = Hex.decode("c37b7e6492584340bed12207808941155068f738");
			byte[] wrap = Hex.decode("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");

			wrapAndUnwrap(kek, key, wrap);

			wrap = Hex.decode("afbeb0f07dfbf5419200f2ccb50bb24f");
			key = Hex.decode("466f7250617369");
			wrapAndUnwrap(kek, key, wrap);

			wrapWithIVTest();

			//
			// offset test
			//
			Wrapper wrapper = new AESWrapPadEngine();

			byte[] pText = new byte[5 + key.Length];
			byte[] cText;

			JavaSystem.arraycopy(key, 0, pText, 5, key.Length);

			wrapper.init(true, new KeyParameter(kek));

			cText = wrapper.wrap(pText, 5, key.Length);
			if (!Arrays.areEqual(cText, wrap))
			{
				fail("failed offset wrap test expected " + StringHelper.NewString(Hex.encode(wrap)) + " got " + StringHelper.NewString(Hex.encode(cText)));
			}

			wrapper.init(false, new KeyParameter(kek));

			cText = new byte[6 + wrap.Length];
			JavaSystem.arraycopy(wrap, 0, cText, 6, wrap.Length);

			pText = wrapper.unwrap(cText, 6, wrap.Length);
			if (!Arrays.areEqual(pText, key))
			{
				fail("failed offset unwrap test expected " + StringHelper.NewString(Hex.encode(key)) + " got " + StringHelper.NewString(Hex.encode(pText)));
			}

			// test random values
			SecureRandom rnd = new SecureRandom();
			for (int i = 0; i < numOfRandomIterations; i++)
			{
				int kekLength = 128;
				bool shouldIncrease = (rnd.nextInt() & 0x01) != 0;
				if (shouldIncrease)
				{
					kekLength = 256;
				}
				kek = new byte[kekLength / 8];
				rnd.nextBytes(kek);
				int keyToWrapSize = RNGUtils.nextInt(rnd, 256 / 8 - 8) + 8;
				byte[] keyToWrap = new byte[keyToWrapSize];
				rnd.nextBytes(keyToWrap);
				wrapAndUnwrap(kek, keyToWrap);
			}
		}

		public static void Main(string[] args)
		{
			runTest(new AESWrapPadTest());
		}
	}


}