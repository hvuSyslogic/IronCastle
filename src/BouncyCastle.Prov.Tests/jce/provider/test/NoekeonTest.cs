using System;

namespace org.bouncycastle.jce.provider.test
{
	using Hex = org.bouncycastle.util.encoders.Hex;


	/// <summary>
	/// basic test class for SEED
	/// </summary>
	public class NoekeonTest : BaseBlockCipherTest
	{
		internal static string[] cipherTests = new string[] {"128", "b1656851699e29fa24b70148503d2dfc", "2a78421b87c7d0924f26113f1d1349b2", "e2f687e07b75660ffc372233bc47532c"};

		public NoekeonTest() : base("Noekeon")
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

			key = new SecretKeySpec(keyBytes, "Noekeon");

			@in = Cipher.getInstance("Noekeon/ECB/NoPadding", "BC");
			@out = Cipher.getInstance("Noekeon/ECB/NoPadding", "BC");

			try
			{
				@out.init(Cipher.ENCRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("Noekeon failed initialisation - " + e.ToString(), e);
			}

			try
			{
				@in.init(Cipher.DECRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("Noekeoen failed initialisation - " + e.ToString(), e);
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
				fail("Noekeon failed encryption - " + e.ToString(), e);
			}

			byte[] bytes;

			bytes = bOut.toByteArray();

			if (!areEqual(bytes, output))
			{
				fail("Noekeon failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
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
				fail("Noekeon failed encryption - " + e.ToString(), e);
			}

			if (!areEqual(bytes, input))
			{
				fail("Noekeon failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
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

			runTest(new NoekeonTest());
		}
	}

}