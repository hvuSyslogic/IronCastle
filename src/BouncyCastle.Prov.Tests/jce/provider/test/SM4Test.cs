using System;

namespace org.bouncycastle.jce.provider.test
{


	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// basic test class for SM4
	/// </summary>
	public class SM4Test : BaseBlockCipherTest
	{
		internal static string[] cipherTests = new string[] {"128", "0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210", "681edf34d206965e86b3e94f536e4246"};

		public SM4Test() : base("SM4")
		{
		}

		public virtual void test(int strength, byte[] keyBytes, byte[] input, byte[] output)
		{
			Key key;
			Cipher @in, @out;
			CipherInputStream cIn;
			CipherOutputStream cOut;
			ByteArrayInputStream bIn;
			ByteArrayOutputStream bOut;

			key = new SecretKeySpec(keyBytes, "SM4");

			@in = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
			@out = Cipher.getInstance("SM4/ECB/NoPadding", "BC");

			try
			{
				@out.init(Cipher.ENCRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("SM4 failed initialisation - " + e.ToString(), e);
			}

			try
			{
				@in.init(Cipher.DECRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("SM4 failed initialisation - " + e.ToString(), e);
			}

			//
			// encryption pass
			//
			bOut = new ByteArrayOutputStream();

			cOut = new CipherOutputStream(bOut, @out);

			try
			{
				for (int i = 0; i != input.Length / 2; i++)
				{
					cOut.write(input[i]);
				}
				cOut.write(input, input.Length / 2, input.Length - input.Length / 2);
				cOut.close();
			}
			catch (IOException e)
			{
				fail("SM4 failed encryption - " + e.ToString(), e);
			}

			byte[] bytes;

			bytes = bOut.toByteArray();

			if (!areEqual(bytes, output))
			{
				fail("SM4 failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}

			//
			// decryption pass
			//
			bIn = new ByteArrayInputStream(bytes);

			cIn = new CipherInputStream(bIn, @in);

			try
			{
				DataInputStream dIn = new DataInputStream(cIn);

				bytes = new byte[input.Length];

				for (int i = 0; i != input.Length / 2; i++)
				{
					bytes[i] = (byte)dIn.read();
				}
				dIn.readFully(bytes, input.Length / 2, bytes.Length - input.Length / 2);
			}
			catch (Exception e)
			{
				fail("SM4 failed encryption - " + e.ToString(), e);
			}

			if (!areEqual(bytes, input))
			{
				fail("SM4 failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}
		}

		public override void performTest()
		{
			for (int i = 0; i != cipherTests.Length; i += 4)
			{
				test(int.Parse(cipherTests[i]), Hex.decode(cipherTests[i + 1]), Hex.decode(cipherTests[i + 2]), Hex.decode(cipherTests[i + 3]));
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new SM4Test());
		}
	}

}