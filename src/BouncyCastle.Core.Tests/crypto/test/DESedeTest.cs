using System;

namespace org.bouncycastle.crypto.test
{
	using DESedeEngine = org.bouncycastle.crypto.engines.DESedeEngine;
	using DESedeWrapEngine = org.bouncycastle.crypto.engines.DESedeWrapEngine;
	using DESedeKeyGenerator = org.bouncycastle.crypto.generators.DESedeKeyGenerator;
	using DESedeParameters = org.bouncycastle.crypto.@params.DESedeParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// DESede tester
	/// </summary>
	public class DESedeTest : CipherTest
	{
		private static byte[] weakKey = new byte[] {(byte)0x06, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x1f, (byte)0x1f, (byte)0x1f, (byte)0x1f, (byte)0x0e, (byte)0x0e, (byte)0x0e, (byte)0x0e, unchecked((byte)0xe0), unchecked((byte)0xe0), unchecked((byte)0xe0), unchecked((byte)0xe0), unchecked((byte)0xf1), unchecked((byte)0xf1), unchecked((byte)0xf1), unchecked((byte)0xf1)};

		internal static string input1 = "4e6f77206973207468652074696d6520666f7220616c6c20";
		internal static string input2 = "4e6f7720697320746865";

		internal static SimpleTest[] tests = new SimpleTest[]
		{
			new BlockCipherVectorTest(0, new DESedeEngine(), new DESedeParameters(Hex.decode("0123456789abcdef0123456789abcdef")), input1, "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53"),
			new BlockCipherVectorTest(1, new DESedeEngine(), new DESedeParameters(Hex.decode("0123456789abcdeffedcba9876543210")), input1, "d80a0d8b2bae5e4e6a0094171abcfc2775d2235a706e232c"),
			new BlockCipherVectorTest(2, new DESedeEngine(), new DESedeParameters(Hex.decode("0123456789abcdef0123456789abcdef0123456789abcdef")), input1, "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53"),
			new BlockCipherVectorTest(3, new DESedeEngine(), new DESedeParameters(Hex.decode("0123456789abcdeffedcba98765432100123456789abcdef")), input1, "d80a0d8b2bae5e4e6a0094171abcfc2775d2235a706e232c")
		};

		public DESedeTest() : base(tests, new DESedeEngine(), new KeyParameter(new byte[16]))
		{
		}

		private void wrapTest(int id, byte[] kek, byte[] iv, byte[] @in, byte[] @out)
		{
			Wrapper wrapper = new DESedeWrapEngine();

			wrapper.init(true, new ParametersWithIV(new KeyParameter(kek), iv));

			try
			{
				byte[] cText = wrapper.wrap(@in, 0, @in.Length);
				if (!areEqual(cText, @out))
				{
					fail(": failed wrap test " + id + " expected " + StringHelper.NewString(Hex.encode(@out)) + " got " + StringHelper.NewString(Hex.encode(cText)));
				}
			}
			catch (Exception e)
			{
				fail("failed wrap test exception: " + e.ToString(), e);
			}

			wrapper.init(false, new KeyParameter(kek));

			try
			{
				byte[] pText = wrapper.unwrap(@out, 0, @out.Length);
				if (!areEqual(pText, @in))
				{
					fail("failed unwrap test " + id + " expected " + StringHelper.NewString(Hex.encode(@in)) + " got " + StringHelper.NewString(Hex.encode(pText)));
				}
			}
			catch (Exception e)
			{
				fail("failed unwrap test exception: " + e.ToString(), e);
			}
		}

		public override void performTest()
		{
			base.performTest();

			byte[] kek1 = Hex.decode("255e0d1c07b646dfb3134cc843ba8aa71f025b7c0838251f");
			byte[] iv1 = Hex.decode("5dd4cbfc96f5453b");
			byte[] in1 = Hex.decode("2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98");
			byte[] out1 = Hex.decode("690107618ef092b3b48ca1796b234ae9fa33ebb4159604037db5d6a84eb3aac2768c632775a467d4");

			wrapTest(1, kek1, iv1, in1, out1);

			//
			// key generation
			//
			SecureRandom random = new SecureRandom();
			DESedeKeyGenerator keyGen = new DESedeKeyGenerator();

			keyGen.init(new KeyGenerationParameters(random, 112));

			byte[] kB = keyGen.generateKey();

			if (kB.Length != 16)
			{
				fail("112 bit key wrong length.");
			}

			keyGen.init(new KeyGenerationParameters(random, 168));

			kB = keyGen.generateKey();

			if (kB.Length != 24)
			{
				fail("168 bit key wrong length.");
			}

			try
			{
				keyGen.init(new KeyGenerationParameters(random, 200));

				fail("invalid key length not detected.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}

			try
			{
				DESedeParameters.isWeakKey(new byte[4], 0);
				fail("no exception on small key");
			}
			catch (IllegalArgumentException e)
			{
				if (!e.getMessage().Equals("key material too short."))
				{
					fail("wrong exception");
				}
			}

			try
			{
				new DESedeParameters(weakKey);
				fail("no exception on weak key");
			}
			catch (IllegalArgumentException e)
			{
				if (!e.getMessage().Equals("attempt to create weak DESede key"))
				{
					fail("wrong exception");
				}
			}
		}

		public override string getName()
		{
			return "DESede";
		}

		public static void Main(string[] args)
		{
			runTest(new DESedeTest());
		}
	}

}