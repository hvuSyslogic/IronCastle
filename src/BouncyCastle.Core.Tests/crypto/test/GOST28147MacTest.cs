namespace org.bouncycastle.crypto.test
{
	using GOST28147Engine = org.bouncycastle.crypto.engines.GOST28147Engine;
	using GOST28147Mac = org.bouncycastle.crypto.macs.GOST28147Mac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithSBox = org.bouncycastle.crypto.@params.ParametersWithSBox;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// GOST 28147 MAC tester 
	/// </summary>
	public class GOST28147MacTest : Test
	{
		//
		// these GOSTMac for testing.
		//
		internal static byte[] gkeyBytes1 = Hex.decode("6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49");
		internal static byte[] gkeyBytes2 = Hex.decode("6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49");

		internal static byte[] input3 = Hex.decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
		internal static byte[] input4 = Hex.decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f");

		internal static byte[] output7 = Hex.decode("93468a46");
		internal static byte[] output8 = Hex.decode("93468a46");

		public GOST28147MacTest()
		{
		}

		public virtual TestResult perform()
		{
			// test1
			Mac mac = new GOST28147Mac();
			KeyParameter key = new KeyParameter(gkeyBytes1);

			mac.init(key);

			mac.update(input3, 0, input3.Length);

			byte[] @out = new byte[4];

			mac.doFinal(@out, 0);

			if (!Arrays.areEqual(@out, output7))
			{
				return new SimpleTestResult(false, getName() + ": Failed test 1 - expected " + StringHelper.NewString(Hex.encode(output7)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			// test2
			key = new KeyParameter(gkeyBytes2);

			ParametersWithSBox gparam = new ParametersWithSBox(key, GOST28147Engine.getSBox("E-A"));

			mac.init(gparam);

			mac.update(input4, 0, input4.Length);

			@out = new byte[4];

			mac.doFinal(@out, 0);

			if (!Arrays.areEqual(@out, output8))
			{
				return new SimpleTestResult(false, getName() + ": Failed test 2 - expected " + StringHelper.NewString(Hex.encode(output8)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public virtual string getName()
		{
			return "GOST28147Mac";
		}

		public static void Main(string[] args)
		{
			GOST28147MacTest test = new GOST28147MacTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}