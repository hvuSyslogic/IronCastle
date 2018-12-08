namespace org.bouncycastle.crypto.test
{
	using NullEngine = org.bouncycastle.crypto.engines.NullEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class NullTest : CipherTest
	{
		internal static SimpleTest[] tests = new SimpleTest[] {new BlockCipherVectorTest(0, new NullEngine(), new KeyParameter(Hex.decode("00")), "00", "00")};

		public NullTest() : base(tests, new NullEngine(), new KeyParameter(new byte[2]))
		{
		}

		public override string getName()
		{
			return "Null";
		}

		public override void performTest()
		{
			base.performTest();

			BlockCipher engine = new NullEngine();

			engine.init(true, null);

			byte[] buf = new byte[1];

			engine.processBlock(buf, 0, buf, 0);

			if (buf[0] != 0)
			{
				fail("NullCipher changed data!");
			}

			byte[] shortBuf = new byte[0];

			try
			{
				engine.processBlock(shortBuf, 0, buf, 0);

				fail("failed short input check");
			}
			catch (DataLengthException)
			{
				// expected 
			}

			try
			{
				engine.processBlock(buf, 0, shortBuf, 0);

				fail("failed short output check");
			}
			catch (DataLengthException)
			{
				// expected 
			}
		}

		public static void Main(string[] args)
		{
			runTest(new NullTest());
		}
	}

}