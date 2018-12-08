namespace org.bouncycastle.crypto.test
{
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using DESKeyGenerator = org.bouncycastle.crypto.generators.DESKeyGenerator;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using CFBBlockCipher = org.bouncycastle.crypto.modes.CFBBlockCipher;
	using OFBBlockCipher = org.bouncycastle.crypto.modes.OFBBlockCipher;
	using DESParameters = org.bouncycastle.crypto.@params.DESParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class DESParityTest : SimpleTest
	{
		public override string getName()
		{
			return "DESParityTest";
		}

		public override void performTest()
		{
			byte[] k1In = new byte[] {unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff)};
			byte[] k1Out = new byte[] {unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe)};

			byte[] k2In = new byte[] {unchecked((byte)0xef), unchecked((byte)0xcb), unchecked((byte)0xda), (byte)0x4f, unchecked((byte)0xaa), unchecked((byte)0x99), (byte)0x7f, (byte)0x63};
			byte[] k2Out = new byte[] {unchecked((byte)0xef), unchecked((byte)0xcb), unchecked((byte)0xda), (byte)0x4f, unchecked((byte)0xab), unchecked((byte)0x98), (byte)0x7f, (byte)0x62};

			DESParameters.setOddParity(k1In);

			for (int i = 0; i != k1In.Length; i++)
			{
				if (k1In[i] != k1Out[i])
				{
					fail("Failed " + "got " + StringHelper.NewString(Hex.encode(k1In))
						+ " expected " + StringHelper.NewString(Hex.encode(k1Out)));
				}
			}

			DESParameters.setOddParity(k2In);

			for (int i = 0; i != k2In.Length; i++)
			{
				if (k2In[i] != k2Out[i])
				{
					fail("Failed " + "got " + StringHelper.NewString(Hex.encode(k2In))
						+ " expected " + StringHelper.NewString(Hex.encode(k2Out)));
				}
			}
		}
	}

	public class KeyGenTest : SimpleTest
	{
		public override string getName()
		{
			return "KeyGenTest";
		}

		public override void performTest()
		{
			DESKeyGenerator keyGen = new DESKeyGenerator();

			keyGen.init(new KeyGenerationParameters(new SecureRandom(), 56));

			byte[] kB = keyGen.generateKey();

			if (kB.Length != 8)
			{
				fail("DES bit key wrong length.");
			}
		}
	}

	public class DESParametersTest : SimpleTest
	{
		private static byte[] weakKeys = new byte[] {(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x1f, (byte)0x1f, (byte)0x1f, (byte)0x1f, (byte)0x0e, (byte)0x0e, (byte)0x0e, (byte)0x0e, unchecked((byte)0xe0), unchecked((byte)0xe0), unchecked((byte)0xe0), unchecked((byte)0xe0), unchecked((byte)0xf1), unchecked((byte)0xf1), unchecked((byte)0xf1), unchecked((byte)0xf1), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x1f, unchecked((byte)0xe0), (byte)0x1f, unchecked((byte)0xe0), (byte)0x0e, unchecked((byte)0xf1), (byte)0x0e, unchecked((byte)0xf1), (byte)0x01, unchecked((byte)0xe0), (byte)0x01, unchecked((byte)0xe0), (byte)0x01, unchecked((byte)0xf1), (byte)0x01, unchecked((byte)0xf1), (byte)0x1f, unchecked((byte)0xfe), (byte)0x1f, unchecked((byte)0xfe), (byte)0x0e, unchecked((byte)0xfe), (byte)0x0e, unchecked((byte)0xfe), (byte)0x01, (byte)0x1f, (byte)0x01, (byte)0x1f, (byte)0x01, (byte)0x0e, (byte)0x01, (byte)0x0e, unchecked((byte)0xe0), unchecked((byte)0xfe), unchecked((byte)0xe0), unchecked((byte)0xfe), unchecked((byte)0xf1), unchecked((byte)0xfe), unchecked((byte)0xf1), unchecked((byte)0xfe), unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xe0), (byte)0x1f, unchecked((byte)0xe0), (byte)0x1f, unchecked((byte)0xf1), (byte)0x0e, unchecked((byte)0xf1), (byte)0x0e, unchecked((byte)0xe0), (byte)0x01, unchecked((byte)0xe0), (byte)0x01, unchecked((byte)0xf1), (byte)0x01, unchecked((byte)0xf1), (byte)0x01, unchecked((byte)0xfe), (byte)0x1f, unchecked((byte)0xfe), (byte)0x1f, unchecked((byte)0xfe), (byte)0x0e, unchecked((byte)0xfe), (byte)0x0e, (byte)0x1f, (byte)0x01, (byte)0x1f, (byte)0x01, (byte)0x0e, (byte)0x01, (byte)0x0e, (byte)0x01, unchecked((byte)0xfe), unchecked((byte)0xe0), unchecked((byte)0xfe), unchecked((byte)0xe0), unchecked((byte)0xfe), unchecked((byte)0xf1), unchecked((byte)0xfe), unchecked((byte)0xf1)};

		public override string getName()
		{
			return "DESParameters";
		}

		public override void performTest()
		{
			try
			{
				DESParameters.isWeakKey(new byte[4], 0);
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
				new DESParameters(weakKeys);
				fail("no exception on weak key");
			}
			catch (IllegalArgumentException e)
			{
				if (!e.getMessage().Equals("attempt to create weak DES key"))
				{
					fail("wrong exception");
				}
			}

			for (int i = 0; i != weakKeys.Length; i += 8)
			{
				if (!DESParameters.isWeakKey(weakKeys, i))
				{
					fail("weakKey test failed");
				}
			}
		}
	}

	/// <summary>
	/// DES tester - vectors from <a href=http://www.itl.nist.gov/fipspubs/fip81.htm>FIPS 81</a>
	/// </summary>
	public class DESTest : CipherTest
	{
		internal static string input1 = "4e6f77206973207468652074696d6520666f7220616c6c20";
		internal static string input2 = "4e6f7720697320746865";
		internal static string input3 = "4e6f7720697320746865aabbcc";

		internal static SimpleTest[] tests = new SimpleTest[]
		{
			new BlockCipherVectorTest(0, new DESEngine(), new KeyParameter(Hex.decode("0123456789abcdef")), input1, "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53"),
			new BlockCipherVectorTest(1, new CBCBlockCipher(new DESEngine()), new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")), input1, "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6"),
			new BlockCipherVectorTest(2, new CFBBlockCipher(new DESEngine(), 8), new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")), input2, "f31fda07011462ee187f"),
			new BlockCipherVectorTest(3, new CFBBlockCipher(new DESEngine(), 64), new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")), input1, "f3096249c7f46e51a69e839b1a92f78403467133898ea622"),
			new BlockCipherVectorTest(4, new OFBBlockCipher(new DESEngine(), 8), new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")), input2, "f34a2850c9c64985d684"),
			new BlockCipherVectorTest(5, new CFBBlockCipher(new DESEngine(), 64), new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")), input3, "f3096249c7f46e51a69e0954bf"),
			new BlockCipherVectorTest(6, new OFBBlockCipher(new DESEngine(), 64), new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")), input3, "f3096249c7f46e5135f2c0eb8b"),
			new DESParityTest(),
			new DESParametersTest(),
			new KeyGenTest()
		};

		public DESTest() : base(tests, new DESEngine(), new KeyParameter(new byte[8]))
		{
		}

		public override string getName()
		{
			return "DES";
		}

		public static void Main(string[] args)
		{
			runTest(new DESTest());
		}
	}

}