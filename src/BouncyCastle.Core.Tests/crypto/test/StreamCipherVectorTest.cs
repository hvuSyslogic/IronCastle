namespace org.bouncycastle.crypto.test
{
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// a basic test that takes a stream cipher, key parameter, and an input
	/// and output string.
	/// </summary>
	public class StreamCipherVectorTest : SimpleTest
	{
		internal int id;
		internal StreamCipher cipher;
		internal CipherParameters param;
		internal byte[] input;
		internal byte[] output;

		public StreamCipherVectorTest(int id, StreamCipher cipher, CipherParameters param, string input, string output)
		{
			this.id = id;
			this.cipher = cipher;
			this.param = param;
			this.input = Hex.decode(input);
			this.output = Hex.decode(output);
		}

		public override string getName()
		{
			return cipher.getAlgorithmName() + " Vector Test " + id;
		}

		public override void performTest()
		{
			cipher.init(true, param);

			byte[] @out = new byte[input.Length];

			cipher.processBytes(input, 0, input.Length, @out, 0);

			if (!areEqual(@out, output))
			{
				fail("failed.", StringHelper.NewString(Hex.encode(output)), StringHelper.NewString(Hex.encode(@out)));
			}

			cipher.init(false, param);

			cipher.processBytes(output, 0, output.Length, @out, 0);

			if (!areEqual(input, @out))
			{
				fail("failed reversal");
			}
		}
	}

}