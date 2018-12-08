namespace org.bouncycastle.crypto.test
{
	using NoekeonEngine = org.bouncycastle.crypto.engines.NoekeonEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// Noekeon tester
	/// </summary>
	public class NoekeonTest : CipherTest
	{
		internal static SimpleTest[] tests = new SimpleTest[]
		{
			new BlockCipherVectorTest(0, new NoekeonEngine(), new KeyParameter(Hex.decode("00000000000000000000000000000000")), "00000000000000000000000000000000", "b1656851699e29fa24b70148503d2dfc"),
			new BlockCipherVectorTest(1, new NoekeonEngine(), new KeyParameter(Hex.decode("ffffffffffffffffffffffffffffffff")), "ffffffffffffffffffffffffffffffff", "2a78421b87c7d0924f26113f1d1349b2"),
			new BlockCipherVectorTest(2, new NoekeonEngine(), new KeyParameter(Hex.decode("b1656851699e29fa24b70148503d2dfc")), "2a78421b87c7d0924f26113f1d1349b2", "e2f687e07b75660ffc372233bc47532c")
		};

		public NoekeonTest() : base(tests, new NoekeonEngine(), new KeyParameter(new byte[16]))
		{
		}

		public override string getName()
		{
			return "Noekeon";
		}

		public static void Main(string[] args)
		{
			runTest(new NoekeonTest());
		}
	}

}