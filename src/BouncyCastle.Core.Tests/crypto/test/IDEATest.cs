namespace org.bouncycastle.crypto.test
{
	using IDEAEngine = org.bouncycastle.crypto.engines.IDEAEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class IDEATest : CipherTest
	{
		internal static SimpleTest[] tests = new SimpleTest[]
		{
			new BlockCipherVectorTest(0, new IDEAEngine(), new KeyParameter(Hex.decode("00112233445566778899AABBCCDDEEFF")), "000102030405060708090a0b0c0d0e0f", "ed732271a7b39f475b4b2b6719f194bf"),
			new BlockCipherVectorTest(0, new IDEAEngine(), new KeyParameter(Hex.decode("00112233445566778899AABBCCDDEEFF")), "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "b8bc6ed5c899265d2bcfad1fc6d4287d")
		};

		public IDEATest() : base(tests, new IDEAEngine(), new KeyParameter(new byte[32]))
		{
		}

		public override string getName()
		{
			return "IDEA";
		}

		public static void Main(string[] args)
		{
			runTest(new IDEATest());
		}
	}

}