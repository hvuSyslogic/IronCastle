namespace org.bouncycastle.crypto.test
{
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class ResetTest : SimpleTest
	{
		private static readonly byte[] input = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");
		private static readonly byte[] output = Hex.decode("3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53");
		public override string getName()
		{
			return "Reset";
		}

		public override void performTest()
		{
			BufferedBlockCipher cipher = new BufferedBlockCipher(new DESEngine());

			KeyParameter param = new KeyParameter(Hex.decode("0123456789abcdef"));

			basicTrial(cipher, param);

			cipher.init(false, param);

			byte[] @out = new byte[input.Length];

			int len2 = cipher.processBytes(output, 0, output.Length - 1, @out, 0);

			try
			{
				cipher.doFinal(@out, len2);
				fail("no DataLengthException - short input");
			}
			catch (DataLengthException)
			{
				// ignore
			}

			len2 = cipher.processBytes(output, 0, output.Length, @out, 0);

			cipher.doFinal(@out, len2);

			if (!areEqual(input, @out))
			{
				fail("failed reversal one got " + StringHelper.NewString(Hex.encode(@out)));
			}

			len2 = cipher.processBytes(output, 0, output.Length - 1, @out, 0);

			try
			{
				cipher.doFinal(@out, len2);
				fail("no DataLengthException - short output");
			}
			catch (DataLengthException)
			{
				// ignore
			}

			len2 = cipher.processBytes(output, 0, output.Length, @out, 0);

			cipher.doFinal(@out, len2);

			if (!areEqual(input, @out))
			{
				fail("failed reversal two got " + StringHelper.NewString(Hex.encode(@out)));
			}
		}

		private void basicTrial(BufferedBlockCipher cipher, KeyParameter param)
		{
			cipher.init(true, param);

			byte[] @out = new byte[input.Length];

			int len1 = cipher.processBytes(input, 0, input.Length, @out, 0);

			cipher.doFinal(@out, len1);

			if (!areEqual(@out, output))
			{
				fail("failed - " + "expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}
		}

		public static void Main(string[] args)
		{
			runTest(new ResetTest());
		}
	}

}