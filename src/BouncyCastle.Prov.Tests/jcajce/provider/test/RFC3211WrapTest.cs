namespace org.bouncycastle.jcajce.provider.test
{



	using TestCase = junit.framework.TestCase;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class RFC3211WrapTest : TestCase
	{
		private const string BC = "BC";

		private static readonly Key KEY_AES128 = new SecretKeySpec(Hex.decode("c794a7735f469c59cf9d7ddd8c65201d"), "AES");
		private static readonly Key KEY_DES = new SecretKeySpec(Hex.decode("8ccbbc15340b46c7cee6e5b6d6b6bc3e08ea38b55d3e08d9"), "DES");

		private static readonly byte[] PLAIN = "abcdefgh".getBytes();

		public virtual void setUp()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}

		public virtual void testAESRFC3211()
		{
			byte[][] res = wrap("AESRFC3211WRAP", KEY_AES128, PLAIN);
			byte[] rv = unwrap("AESRFC3211WRAP", KEY_AES128, res);

			assertTrue(Arrays.areEqual(PLAIN, rv));

			byte[] iv = Hex.decode("0f0e0d0c0b0a00010203040506070809");

			res = wrapWithIV("AESRFC3211WRAP", KEY_AES128, PLAIN, iv);

			assertTrue(Arrays.areEqual(iv, res[0]));

			rv = unwrap("AESRFC3211WRAP", KEY_AES128, res);

			assertTrue(Arrays.areEqual(PLAIN, rv));

			assertTrue(Arrays.areEqual(PLAIN, doWithAlgParams("AESRFC3211WRAP", KEY_AES128, PLAIN)));
		}

		public virtual void testAESRFC3211Bounds()
		{
			byte[] plain = genInput(255);
			byte[][] res = wrap("AESRFC3211WRAP", KEY_AES128, plain);
			byte[] rv = unwrap("AESRFC3211WRAP", KEY_AES128, res);

			assertTrue(Arrays.areEqual(plain, rv));

			plain = new byte[0];
			res = wrap("AESRFC3211WRAP", KEY_AES128, plain);
			rv = unwrap("AESRFC3211WRAP", KEY_AES128, res);

			assertTrue(Arrays.areEqual(plain, rv));
		}

		public virtual void testAESRFC3211Exception()
		{
			doExceptionTests("AESRFC3211WRAP", KEY_AES128);
		}

		public virtual void testTDESRFC3211()
		{
			byte[][] res = wrap("DESEDERFC3211WRAP", KEY_DES, PLAIN);
			byte[] rv = unwrap("DESEDERFC3211WRAP", KEY_DES, res);

			assertTrue(Arrays.areEqual(PLAIN, rv));

			byte[] iv = Hex.decode("0102030405060708");

			res = wrapWithIV("DESEDERFC3211WRAP", KEY_DES, PLAIN, iv);

			assertTrue(Arrays.areEqual(iv, res[0]));

			rv = unwrap("DESEDERFC3211WRAP", KEY_DES, res);

			assertTrue(Arrays.areEqual(PLAIN, rv));

			assertTrue(Arrays.areEqual(PLAIN, doWithAlgParams("DESEDERFC3211WRAP", KEY_DES, PLAIN)));
		}

		public virtual void testTDESRFC3211Bounds()
		{
			byte[] plain = genInput(255);
			byte[][] res = wrap("DESEDERFC3211WRAP", KEY_DES, plain);
			byte[] rv = unwrap("DESEDERFC3211WRAP", KEY_DES, res);

			assertTrue(Arrays.areEqual(plain, rv));

			plain = new byte[0];
			res = wrap("DESEDERFC3211WRAP", KEY_DES, plain);
			rv = unwrap("DESEDERFC3211WRAP", KEY_DES, res);

			assertTrue(Arrays.areEqual(plain, rv));
		}

		public virtual void testTDESRFC3211Exception()
		{
			doExceptionTests("DESEDERFC3211WRAP", KEY_DES);
		}

		private static void doExceptionTests(string alg, Key key)
		{
			byte[] plain = genInput(256);
			try
			{
				wrap(alg, key, plain);

				fail("no exception");
			}
			catch (IllegalBlockSizeException e)
			{
				assertEquals("input must be from 0 to 255 bytes", e.Message);
			}

			try
			{
				Cipher engine = Cipher.getInstance(alg, "BC");
				engine.init(Cipher.ENCRYPT_MODE, key);
				engine.doFinal(plain, 0, plain.Length, new byte[500]);
				fail("no exception");
			}
			catch (IllegalBlockSizeException e)
			{
				assertEquals("input must be from 0 to 255 bytes", e.Message);
			}

			try
			{
				Cipher engine = Cipher.getInstance(alg, "BC");
				engine.init(Cipher.DECRYPT_MODE, key);
				fail("no exception");
			}
			catch (InvalidKeyException e)
			{
				assertEquals("RFC3211Wrap requires an IV", e.Message);
			}
		}

		private static byte[] genInput(int len)
		{
			byte[] rv = new byte[len];

			for (int i = 0; i != len; i++)
			{
				rv[i] = (byte)i;
			}

			return rv;
		}

		private static byte[] doWithAlgParams(string algo, Key privKey, byte[] data)
		{
			Cipher engine = Cipher.getInstance(algo, BC);
			engine.init(Cipher.ENCRYPT_MODE, privKey);
			byte[] res = engine.doFinal(data);
			AlgorithmParameters algParams = engine.getParameters();
			engine = Cipher.getInstance(algo, BC);
			engine.init(Cipher.DECRYPT_MODE, privKey, algParams);

			return engine.doFinal(res);
		}

		private static byte[][] wrap(string algo, Key privKey, byte[] data)
		{
			Cipher engine = Cipher.getInstance(algo, "BC");
			engine.init(Cipher.ENCRYPT_MODE, privKey);
			byte[] res = engine.doFinal(data);
			return new byte[][]{engine.getIV(), res};
		}

		private static byte[][] wrapWithIV(string algo, Key privKey, byte[] data, byte[] iv)
		{
			Cipher engine = Cipher.getInstance(algo, "BC");
			engine.init(Cipher.ENCRYPT_MODE, privKey, new IvParameterSpec(iv));
			byte[] res = engine.doFinal(data);
			return new byte[][]{engine.getIV(), res};
		}

		private static byte[] unwrap(string algo, Key privKey, byte[][] data)
		{
			Cipher engine = Cipher.getInstance(algo, "BC");
			engine.init(Cipher.DECRYPT_MODE, privKey, new IvParameterSpec(data[0]));
			return engine.doFinal(data[1]);
		}
	}
}