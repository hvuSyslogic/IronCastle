namespace org.bouncycastle.crypto.test
{
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using CBCBlockCipherMac = org.bouncycastle.crypto.macs.CBCBlockCipherMac;
	using CFBBlockCipherMac = org.bouncycastle.crypto.macs.CFBBlockCipherMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using PKCS7Padding = org.bouncycastle.crypto.paddings.PKCS7Padding;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// MAC tester - vectors from 
	/// <a href=http://www.itl.nist.gov/fipspubs/fip81.htm>FIP 81</a> and 
	/// <a href=http://www.itl.nist.gov/fipspubs/fip113.htm>FIP 113</a>.
	/// </summary>
	public class MacTest : SimpleTest
	{
		internal static byte[] keyBytes = Hex.decode("0123456789abcdef");
		internal static byte[] ivBytes = Hex.decode("1234567890abcdef");

		internal static byte[] input1 = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f7220");

		internal static byte[] output1 = Hex.decode("f1d30f68");
		internal static byte[] output2 = Hex.decode("58d2e77e");
		internal static byte[] output3 = Hex.decode("cd647403");

		//
		// these aren't NIST vectors, just for regression testing.
		//
		internal static byte[] input2 = Hex.decode("3736353433323120");

		internal static byte[] output4 = Hex.decode("3af549c9");
		internal static byte[] output5 = Hex.decode("188fbdd5");
		internal static byte[] output6 = Hex.decode("7045eecd");

		public MacTest()
		{
		}

		public override void performTest()
		{
			KeyParameter key = new KeyParameter(keyBytes);
			BlockCipher cipher = new DESEngine();
			Mac mac = new CBCBlockCipherMac(cipher);

			//
			// standard DAC - zero IV
			//
			mac.init(key);

			mac.update(input1, 0, input1.Length);

			byte[] @out = new byte[4];

			mac.doFinal(@out, 0);

			if (!areEqual(@out, output1))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output1)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			// mac with IV.
			//
			ParametersWithIV param = new ParametersWithIV(key, ivBytes);

			mac.init(param);

			mac.update(input1, 0, input1.Length);

			@out = new byte[4];

			mac.doFinal(@out, 0);

			if (!areEqual(@out, output2))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output2)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			// CFB mac with IV - 8 bit CFB mode
			//
			param = new ParametersWithIV(key, ivBytes);

			mac = new CFBBlockCipherMac(cipher);

			mac.init(param);

			mac.update(input1, 0, input1.Length);

			@out = new byte[4];

			mac.doFinal(@out, 0);

			if (!areEqual(@out, output3))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output3)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			// word aligned data - zero IV
			//
			mac.init(key);

			mac.update(input2, 0, input2.Length);

			@out = new byte[4];

			mac.doFinal(@out, 0);

			if (!areEqual(@out, output4))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output4)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			// word aligned data - zero IV - CBC padding
			//
			mac = new CBCBlockCipherMac(cipher, new PKCS7Padding());

			mac.init(key);

			mac.update(input2, 0, input2.Length);

			@out = new byte[4];

			mac.doFinal(@out, 0);

			if (!areEqual(@out, output5))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output5)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			// non-word aligned data - zero IV - CBC padding
			//
			mac.reset();

			mac.update(input1, 0, input1.Length);

			@out = new byte[4];

			mac.doFinal(@out, 0);

			if (!areEqual(@out, output6))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output6)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			// non-word aligned data - zero IV - CBC padding
			//
			mac.init(key);

			mac.update(input1, 0, input1.Length);

			@out = new byte[4];

			mac.doFinal(@out, 0);

			if (!areEqual(@out, output6))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output6)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}
		}

		public override string getName()
		{
			return "Mac";
		}

		public static void Main(string[] args)
		{
			runTest(new MacTest());
		}
	}

}