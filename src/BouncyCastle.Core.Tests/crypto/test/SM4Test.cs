namespace org.bouncycastle.crypto.test
{
	using SM4Engine = org.bouncycastle.crypto.engines.SM4Engine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// SM4 tester, vectors from <a href="http://eprint.iacr.org/2008/329.pdf">http://eprint.iacr.org/2008/329.pdf</a>
	/// </summary>
	public class SM4Test : CipherTest
	{
		internal static SimpleTest[] tests = new SimpleTest[] {new BlockCipherVectorTest(0, new SM4Engine(), new KeyParameter(Hex.decode("0123456789abcdeffedcba9876543210")), "0123456789abcdeffedcba9876543210", "681edf34d206965e86b3e94f536e4246")};

		public SM4Test() : base(tests, new SM4Engine(), new KeyParameter(new byte[16]))
		{
		}

		public override void performTest()
		{
			base.performTest();

			test1000000();
		}

		private void test1000000()
		{
			byte[] plain = Hex.decode("0123456789abcdeffedcba9876543210");
			byte[] key = Hex.decode("0123456789abcdeffedcba9876543210");
			byte[] cipher = Hex.decode("595298c7c6fd271f0402f804c33d3f66");
			byte[] buf = new byte[16];

			BlockCipher engine = new SM4Engine();

			engine.init(true, new KeyParameter(key));

			JavaSystem.arraycopy(plain, 0, buf, 0, buf.Length);

			for (int i = 0; i != 1000000; i++)
			{
				engine.processBlock(buf, 0, buf, 0);
			}

			if (!areEqual(cipher, buf))
			{
				fail("1000000 encryption test failed");
			}

			engine.init(false, new KeyParameter(key));

			for (int i = 0; i != 1000000; i++)
			{
				engine.processBlock(buf, 0, buf, 0);
			}

			if (!areEqual(plain, buf))
			{
				fail("1000000 decryption test failed");
			}
		}

		public override string getName()
		{
			return "SM4";
		}

		public static void Main(string[] args)
		{
			runTest(new SM4Test());
		}
	}

}