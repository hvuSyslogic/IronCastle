namespace org.bouncycastle.crypto.test
{
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using CFBBlockCipher = org.bouncycastle.crypto.modes.CFBBlockCipher;
	using OFBBlockCipher = org.bouncycastle.crypto.modes.OFBBlockCipher;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// CFB/OFB Mode test of IV padding.
	/// </summary>
	public class ModeTest : Test
	{
		public ModeTest()
		{
		}

		private bool isEqualTo(byte[] a, byte[] b)
		{
			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		public virtual TestResult perform()
		{
			KeyParameter key = new KeyParameter(Hex.decode("0011223344556677"));
			byte[] input = Hex.decode("4e6f7720");
			byte[] out1 = new byte[4];
			byte[] out2 = new byte[4];


			BlockCipher ofb = new OFBBlockCipher(new DESEngine(), 32);

			ofb.init(true, new ParametersWithIV(key, Hex.decode("1122334455667788")));

			ofb.processBlock(input, 0, out1, 0);

			ofb.init(false, new ParametersWithIV(key, Hex.decode("1122334455667788")));
			ofb.processBlock(out1, 0, out2, 0);

			if (!isEqualTo(out2, input))
			{
				return new SimpleTestResult(false, getName() + ": test 1 - in != out");
			}

			ofb.init(true, new ParametersWithIV(key, Hex.decode("11223344")));

			ofb.processBlock(input, 0, out1, 0);

			ofb.init(false, new ParametersWithIV(key, Hex.decode("0000000011223344")));
			ofb.processBlock(out1, 0, out2, 0);

			if (!isEqualTo(out2, input))
			{
				return new SimpleTestResult(false, getName() + ": test 2 - in != out");
			}

			BlockCipher cfb = new CFBBlockCipher(new DESEngine(), 32);

			cfb.init(true, new ParametersWithIV(key, Hex.decode("1122334455667788")));

			cfb.processBlock(input, 0, out1, 0);

			cfb.init(false, new ParametersWithIV(key, Hex.decode("1122334455667788")));
			cfb.processBlock(out1, 0, out2, 0);

			if (!isEqualTo(out2, input))
			{
				return new SimpleTestResult(false, getName() + ": test 3 - in != out");
			}

			cfb.init(true, new ParametersWithIV(key, Hex.decode("11223344")));

			cfb.processBlock(input, 0, out1, 0);

			cfb.init(false, new ParametersWithIV(key, Hex.decode("0000000011223344")));
			cfb.processBlock(out1, 0, out2, 0);

			if (!isEqualTo(out2, input))
			{
				return new SimpleTestResult(false, getName() + ": test 4 - in != out");
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public virtual string getName()
		{
			return "ModeTest";
		}

		public static void Main(string[] args)
		{
			ModeTest test = new ModeTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}