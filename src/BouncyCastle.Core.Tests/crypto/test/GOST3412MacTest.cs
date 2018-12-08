namespace org.bouncycastle.crypto.test
{
	using GOST3412_2015Engine = org.bouncycastle.crypto.engines.GOST3412_2015Engine;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// see GOST_R_3413-2015
	/// </summary>
	public class GOST3412MacTest : Test
	{

		public virtual string getName()
		{
			return "GOST 3412 2015 MAC test";
		}

		public virtual TestResult perform()
		{


			byte[][] inputs = new byte[][]{Hex.decode("1122334455667700ffeeddccbbaa9988"), Hex.decode("00112233445566778899aabbcceeff0a"), Hex.decode("112233445566778899aabbcceeff0a00"), Hex.decode("2233445566778899aabbcceeff0a0011")};
			Mac mac = new CMac(new GOST3412_2015Engine(), 64);

			byte[] output = Hex.decode("336f4d296059fbe3");

			KeyParameter key = new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"));
			mac.init(key);

			for (int i = 0; i != inputs.Length; i++)
			{
				mac.update(inputs[i], 0, inputs[i].Length);
			}

			byte[] @out = new byte[8];

			mac.doFinal(@out, 0);

			if (!Arrays.areEqual(@out, output))
			{
				return new SimpleTestResult(false, getName() + ": Failed test 1 - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			return new SimpleTestResult(true, getName() + ": Okay");

		}


		public static void Main(string[] args)
		{
			GOST3412MacTest test = new GOST3412MacTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}


	}

}