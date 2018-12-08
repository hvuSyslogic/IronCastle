namespace org.bouncycastle.crypto.test
{
	using SkipjackEngine = org.bouncycastle.crypto.engines.SkipjackEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class SkipjackTest : CipherTest
	{
		internal static SimpleTest[] tests = new SimpleTest[] {new BlockCipherVectorTest(0, new SkipjackEngine(), new KeyParameter(Hex.decode("00998877665544332211")), "33221100ddccbbaa", "2587cae27a12d300")};

		public SkipjackTest() : base(tests, new SkipjackEngine(), new KeyParameter(Hex.decode("00998877665544332211")))
		{
		}

		public override string getName()
		{
			return "SKIPJACK";
		}

		public static void Main(string[] args)
		{
			runTest(new SkipjackTest());
		}
	}

}