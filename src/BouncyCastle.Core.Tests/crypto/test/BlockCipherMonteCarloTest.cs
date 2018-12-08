namespace org.bouncycastle.crypto.test
{
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// a basic test that takes a cipher, key parameter, and an input
	/// and output string. This test wraps the engine in a buffered block
	/// cipher with padding disabled.
	/// </summary>
	public class BlockCipherMonteCarloTest : SimpleTest
	{
		internal int id;
		internal int iterations;
		internal BlockCipher engine;
		internal CipherParameters param;
		internal byte[] input;
		internal byte[] output;

		public BlockCipherMonteCarloTest(int id, int iterations, BlockCipher engine, CipherParameters param, string input, string output)
		{
			this.id = id;
			this.iterations = iterations;
			this.engine = engine;
			this.param = param;
			this.input = Hex.decode(input);
			this.output = Hex.decode(output);
		}

		public override string getName()
		{
			return engine.getAlgorithmName() + " Monte Carlo Test " + id;
		}

		public override void performTest()
		{
			BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

			cipher.init(true, param);

			byte[] @out = new byte[input.Length];

			JavaSystem.arraycopy(input, 0, @out, 0, @out.Length);

			for (int i = 0; i != iterations; i++)
			{
				int len1 = cipher.processBytes(@out, 0, @out.Length, @out, 0);

				cipher.doFinal(@out, len1);
			}

			if (!areEqual(@out, output))
			{
				fail("failed - " + "expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			cipher.init(false, param);

			for (int i = 0; i != iterations; i++)
			{
				int len1 = cipher.processBytes(@out, 0, @out.Length, @out, 0);

				cipher.doFinal(@out, len1);
			}

			if (!areEqual(input, @out))
			{
				fail("failed reversal");
			}
		}
	}

}