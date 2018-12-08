namespace org.bouncycastle.crypto.test
{
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// a basic test that takes a cipher, key parameter, and an input
	/// and output string. This test wraps the engine in a buffered block
	/// cipher with padding disabled.
	/// </summary>
	public class BlockCipherVectorTest : SimpleTest
	{
		internal int id;
		internal BlockCipher engine;
		internal CipherParameters param;
		internal byte[] input;
		internal byte[] output;

		public BlockCipherVectorTest(int id, BlockCipher engine, CipherParameters param, string input, string output)
		{
			this.id = id;
			this.engine = engine;
			this.param = param;
			this.input = Hex.decode(input);
			this.output = Hex.decode(output);
		}

		public override string getName()
		{
			return engine.getAlgorithmName() + " Vector Test " + id;
		}

		public override void performTest()
		{
			BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

			cipher.init(true, param);

			byte[] @out = new byte[input.Length];

			int len1 = cipher.processBytes(input, 0, input.Length, @out, 0);

			cipher.doFinal(@out, len1);

			if (!areEqual(@out, output))
			{
				fail("failed - " + "expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			cipher.init(false, param);

			int len2 = cipher.processBytes(output, 0, output.Length, @out, 0);

			cipher.doFinal(@out, len2);

			if (!areEqual(input, @out))
			{
				JavaSystem.@out.println(" got " + StringHelper.NewString(Hex.encode(@out)));

				fail("failed reversal - " + "expected " + StringHelper.NewString(Hex.encode(input)));
			}
		}
	}

}