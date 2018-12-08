namespace org.bouncycastle.jce.provider.test
{


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

		internal static byte[] input = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f7220");

		internal static byte[] output1 = Hex.decode("f1d30f68");
		internal static byte[] output2 = Hex.decode("58d2e77e");
		internal static byte[] output3 = Hex.decode("cd647403");

		internal static byte[] keyBytesISO9797 = Hex.decode("7CA110454A1A6E570131D9619DC1376E");

		internal static byte[] inputISO9797 = "Hello World !!!!".getBytes();

		internal static byte[] outputISO9797 = Hex.decode("F09B856213BAB83B");

		internal static byte[] inputDesEDE64 = "Hello World !!!!".getBytes();

		internal static byte[] outputDesEDE64 = Hex.decode("862304d33af01096");

		public MacTest()
		{
		}

		private void aliasTest(SecretKey key, string primary, string[] aliases)
		{
			Mac mac = Mac.getInstance(primary, "BC");

			//
			// standard DAC - zero IV
			//
			mac.init(key);

			mac.update(input, 0, input.Length);

			byte[] @ref = mac.doFinal();

			for (int i = 0; i != aliases.Length; i++)
			{
				mac = Mac.getInstance(aliases[i], "BC");

				mac.init(key);

				mac.update(input, 0, input.Length);

				byte[] @out = mac.doFinal();
				if (!areEqual(@out, @ref))
				{
					fail("Failed - expected " + StringHelper.NewString(Hex.encode(@ref)) + " got " + StringHelper.NewString(Hex.encode(@out)));
				}
			}
		}

		public override void performTest()
		{
			SecretKey key = new SecretKeySpec(keyBytes, "DES");
			byte[] @out;
			Mac mac;

			mac = Mac.getInstance("DESMac", "BC");

			//
			// standard DAC - zero IV
			//
			mac.init(key);

			mac.update(input, 0, input.Length);

			@out = mac.doFinal();

			if (!areEqual(@out, output1))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output1)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			// mac with IV.
			//
			mac.init(key, new IvParameterSpec(ivBytes));

			mac.update(input, 0, input.Length);

			@out = mac.doFinal();

			if (!areEqual(@out, output2))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output2)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			// CFB mac with IV - 8 bit CFB mode
			//
			mac = Mac.getInstance("DESMac/CFB8", "BC");

			mac.init(key, new IvParameterSpec(ivBytes));

			mac.update(input, 0, input.Length);

			@out = mac.doFinal();

			if (!areEqual(@out, output3))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output3)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			// ISO9797 algorithm 3 using DESEDE
			//
			key = new SecretKeySpec(keyBytesISO9797, "DESEDE");

			mac = Mac.getInstance("ISO9797ALG3", "BC");

			mac.init(key);

			mac.update(inputISO9797, 0, inputISO9797.Length);

			@out = mac.doFinal();

			if (!areEqual(@out, outputISO9797))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(outputISO9797)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			//
			// 64bit DESede Mac
			//
			key = new SecretKeySpec(keyBytesISO9797, "DESEDE");

			mac = Mac.getInstance("DESEDE64", "BC");

			mac.init(key);

			mac.update(inputDesEDE64, 0, inputDesEDE64.Length);

			@out = mac.doFinal();

			if (!areEqual(@out, outputDesEDE64))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(outputDesEDE64)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}

			aliasTest(new SecretKeySpec(keyBytesISO9797, "DESede"), "DESedeMac64withISO7816-4Padding", new string[] {"DESEDE64WITHISO7816-4PADDING", "DESEDEISO9797ALG1MACWITHISO7816-4PADDING", "DESEDEISO9797ALG1WITHISO7816-4PADDING"});

			aliasTest(new SecretKeySpec(keyBytesISO9797, "DESede"), "ISO9797ALG3WITHISO7816-4PADDING", new string[] {"ISO9797ALG3MACWITHISO7816-4PADDING"});

			aliasTest(new SecretKeySpec(keyBytes, "DES"), "DES64", new string[] {"DESMAC64"});
		}

		public override string getName()
		{
			return "Mac";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new MacTest());
		}
	}

}