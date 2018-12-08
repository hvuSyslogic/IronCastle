namespace org.bouncycastle.crypto.test
{
	using TwofishEngine = org.bouncycastle.crypto.engines.TwofishEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class TwofishTest : CipherTest
	{
		internal static string key1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
		internal static string key2 = "000102030405060708090a0b0c0d0e0f1011121314151617";
		internal static string key3 = "000102030405060708090a0b0c0d0e0f";

		internal static string input = "000102030405060708090A0B0C0D0E0F";

		internal static SimpleTest[] tests = new SimpleTest[]
		{
			new BlockCipherVectorTest(0, new TwofishEngine(), new KeyParameter(Hex.decode(key1)), input, "8ef0272c42db838bcf7b07af0ec30f38"),
			new BlockCipherVectorTest(1, new TwofishEngine(), new KeyParameter(Hex.decode(key2)), input, "95accc625366547617f8be4373d10cd7"),
			new BlockCipherVectorTest(2, new TwofishEngine(), new KeyParameter(Hex.decode(key3)), input, "9fb63337151be9c71306d159ea7afaa4")
		};

		public TwofishTest() : base(tests, new TwofishEngine(), new KeyParameter(new byte[32]))
		{
		}

		public override string getName()
		{
			return "Twofish";
		}

		public static void Main(string[] args)
		{
			runTest(new TwofishTest());
		}
	}

}