namespace org.bouncycastle.jce.provider.test
{


	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// basic test class for the GOST28147 cipher
	/// </summary>
	public class GOST3412Test : SimpleTest
	{
		public override string getName()
		{
			return "GOST3412";
		}

		public virtual void testECB(byte[] keyBytes, byte[] input, byte[] output)
		{
			Key key;
			Cipher @in, @out;
			CipherInputStream cIn;
			CipherOutputStream cOut;
			ByteArrayInputStream bIn;
			ByteArrayOutputStream bOut;

			key = new SecretKeySpec(keyBytes, "GOST3412-2015");

			@in = Cipher.getInstance("GOST3412-2015/ECB/NoPadding", "BC");
			@out = Cipher.getInstance("GOST3412-2015/ECB/NoPadding", "BC");
			@out.init(Cipher.ENCRYPT_MODE, key);
			@in.init(Cipher.DECRYPT_MODE, key);

			//
			// encryption pass
			//
			bOut = new ByteArrayOutputStream();

			cOut = new CipherOutputStream(bOut, @out);

			for (int i = 0; i != input.Length / 2; i++)
			{
				cOut.write(input[i]);
			}
			cOut.write(input, input.Length / 2, input.Length - input.Length / 2);
			cOut.close();

			byte[] bytes;

			bytes = bOut.toByteArray();

			if (!areEqual(bytes, output))
			{
				fail("GOST3412-2015 failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}

			//
			// decryption pass
			//
			bIn = new ByteArrayInputStream(bytes);

			cIn = new CipherInputStream(bIn, @in);

			DataInputStream dIn = new DataInputStream(cIn);

			bytes = new byte[input.Length];

			for (int i = 0; i != input.Length / 2; i++)
			{
				bytes[i] = (byte)dIn.read();
			}
			dIn.readFully(bytes, input.Length / 2, bytes.Length - input.Length / 2);

			if (!areEqual(bytes, input))
			{
				fail("GOST3412-2015 failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}
		}

		public virtual void testCFB(byte[] keyBytes, byte[] iv, byte[] input, byte[] output)
		{
			Key key;
			Cipher @in, @out;
			CipherInputStream cIn;
			CipherOutputStream cOut;
			ByteArrayInputStream bIn;
			ByteArrayOutputStream bOut;

			key = new SecretKeySpec(keyBytes, "GOST3412-2015");

			@in = Cipher.getInstance("GOST3412-2015/CFB8/NoPadding", "BC");
			@out = Cipher.getInstance("GOST3412-2015/CFB8/NoPadding", "BC");

			@out.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			@in.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

			//
			// encryption pass
			//
			bOut = new ByteArrayOutputStream();

			cOut = new CipherOutputStream(bOut, @out);

			for (int i = 0; i != input.Length / 2; i++)
			{
				cOut.write(input[i]);
			}
			cOut.write(input, input.Length / 2, input.Length - input.Length / 2);
			cOut.close();

			byte[] bytes;

			bytes = bOut.toByteArray();

			if (!areEqual(bytes, output))
			{
				fail("GOST3412-2015 failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}

			//
			// decryption pass
			//
			bIn = new ByteArrayInputStream(bytes);

			cIn = new CipherInputStream(bIn, @in);

			DataInputStream dIn = new DataInputStream(cIn);

			bytes = new byte[input.Length];

			for (int i = 0; i != input.Length / 2; i++)
			{
				bytes[i] = (byte)dIn.read();
			}
			dIn.readFully(bytes, input.Length / 2, bytes.Length - input.Length / 2);

			if (!areEqual(bytes, input))
			{
				fail("GOST3412-2015 failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}
		}

		public override void performTest()
		{
			testECB(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"), Hex.decode("1122334455667700ffeeddccbbaa9988"), Hex.decode("7f679d90bebc24305a468d42b9d4edcd"));

			testCFB(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"), Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819"), Hex.decode("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011"), Hex.decode("819b19c5867e61f1cf1b16f664f66e46ed8fcb82b1110b1e7ec03bfa6611f2eabd7a32363691cbdc3bbe403bc80552d822c2cdf483981cd71d5595453d7f057d"));

			byte[][] inputs = new byte[][]{Hex.decode("1122334455667700ffeeddccbbaa9988"), Hex.decode("00112233445566778899aabbcceeff0a"), Hex.decode("112233445566778899aabbcceeff0a00"), Hex.decode("2233445566778899aabbcceeff0a0011")};

			Mac mac = Mac.getInstance("GOST3412MAC", "BC");

			mac.init(new SecretKeySpec(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"), "GOST3412MAC"));

			for (int i = 0; i != inputs.Length; i++)
			{
				mac.update(inputs[i]);
			}

			if (!Arrays.areEqual(Hex.decode("336f4d296059fbe34ddeb35b37749c67"), mac.doFinal()))
			{
				fail("mac test failed.");
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new GOST3412Test());
		}
	}

}