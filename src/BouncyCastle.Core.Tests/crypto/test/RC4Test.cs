namespace org.bouncycastle.crypto.test
{
	using RC4Engine = org.bouncycastle.crypto.engines.RC4Engine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// RC4 Test
	/// </summary>
	public class RC4Test : SimpleTest
	{
		internal StreamCipherVectorTest[] tests = new StreamCipherVectorTest[]
		{
			new StreamCipherVectorTest(0, new RC4Engine(), new KeyParameter(Hex.decode("0123456789ABCDEF")), "4e6f772069732074", "3afbb5c77938280d"),
			new StreamCipherVectorTest(0, new RC4Engine(), new KeyParameter(Hex.decode("0123456789ABCDEF")), "68652074696d6520", "1cf1e29379266d59"),
			new StreamCipherVectorTest(0, new RC4Engine(), new KeyParameter(Hex.decode("0123456789ABCDEF")), "666f7220616c6c20", "12fbb0c771276459")
		};

		public override string getName()
		{
			return "RC4";
		}

		public override void performTest()
		{
			for (int i = 0; i != tests.Length; i++)
			{
				tests[i].performTest();
			}
		}

		public static void Main(string[] args)
		{
			runTest(new RC4Test());
		}
	}

}