using System;

namespace org.bouncycastle.jce.provider.test
{


	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// basic test class for key generation for a DES-EDE block cipher, basically
	/// this just exercises the provider, and makes sure we are behaving sensibly,
	/// correctness of the implementation is shown in the lightweight test classes.
	/// </summary>
	public class DESedeTest : SimpleTest
	{
		internal static string[] cipherTests1 = new string[] {"112", "2f4bc6b30c893fa549d82c560d61cf3eb088aed020603de249d82c560d61cf3e529e95ecd8e05394", "128", "2f4bc6b30c893fa549d82c560d61cf3eb088aed020603de249d82c560d61cf3e529e95ecd8e05394", "168", "50ddb583a25c21e6c9233f8e57a86d40bb034af421c03096c9233f8e57a86d402fce91e8eb639f89", "192", "50ddb583a25c21e6c9233f8e57a86d40bb034af421c03096c9233f8e57a86d402fce91e8eb639f89"};

		internal static byte[] input1 = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f");

		/// <summary>
		/// a fake random number generator - we just want to make sure the random numbers
		/// aren't random so that we get the same output, while still getting to test the
		/// key generation facilities.
		/// </summary>
		public class FixedSecureRandom : SecureRandom
		{
			private readonly DESedeTest outerInstance;

			public FixedSecureRandom(DESedeTest outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			internal byte[] seed = new byte[] {unchecked((byte)0xaa), unchecked((byte)0xfd), (byte)0x12, unchecked((byte)0xf6), (byte)0x59, unchecked((byte)0xca), unchecked((byte)0xe6), (byte)0x34, unchecked((byte)0x89), unchecked((byte)0xb4), (byte)0x79, unchecked((byte)0xe5), (byte)0x07, (byte)0x6d, unchecked((byte)0xde), unchecked((byte)0xc2), unchecked((byte)0xf0), (byte)0x6c, unchecked((byte)0xb5), unchecked((byte)0x8f)};

			public virtual void nextBytes(byte[] bytes)
			{
				int offset = 0;

				while ((offset + seed.Length) < bytes.Length)
				{
					JavaSystem.arraycopy(seed, 0, bytes, offset, seed.Length);
					offset += seed.Length;
				}

				JavaSystem.arraycopy(seed, 0, bytes, offset, bytes.Length - offset);
			}
		}

		public override string getName()
		{
			return "DESEDE";
		}

		private bool equalArray(byte[] a, byte[] b)
		{
			if (a.Length != b.Length)
			{
				return false;
			}

			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		private bool equalArray(byte[] a, byte[] b, int length)
		{
			if (a.Length < length)
			{
				return false;
			}

			if (b.Length < length)
			{
				return false;
			}

			for (int i = 0; i != length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		private void wrapTest(string alg, int id, byte[] kek, byte[] iv, byte[] @in, byte[] @out)
		{
			try
			{
				Cipher wrapper = Cipher.getInstance(alg + "Wrap", "BC");

				wrapper.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, alg), new IvParameterSpec(iv));

				try
				{
					byte[] cText = wrapper.wrap(new SecretKeySpec(@in, alg));
					if (!equalArray(cText, @out))
					{
						fail("failed wrap test " + id + " expected " + StringHelper.NewString(Hex.encode(@out)) + " got " + StringHelper.NewString(Hex.encode(cText)));
					}
				}
				catch (Exception e)
				{
					fail("failed wrap test exception " + e.ToString());
				}

				wrapper.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, alg));

				try
				{
					Key pText = wrapper.unwrap(@out, alg, Cipher.SECRET_KEY);
					if (!equalArray(pText.getEncoded(), @in))
					{
						fail("failed unwrap test " + id + " expected " + StringHelper.NewString(Hex.encode(@in)) + " got " + StringHelper.NewString(Hex.encode(pText.getEncoded())));
					}
				}
				catch (Exception e)
				{
					fail("failed unwrap test exception " + e.ToString());
				}
			}
			catch (Exception ex)
			{
				fail("failed exception " + ex.ToString());
			}
		}

		public virtual void test(string alg, int strength, byte[] input, byte[] output)
		{
			Key key = null;
			KeyGenerator keyGen;
			SecureRandom rand;
			Cipher @in = null;
			Cipher @out = null;
			CipherInputStream cIn;
			CipherOutputStream cOut;
			ByteArrayInputStream bIn;
			ByteArrayOutputStream bOut;

			rand = new FixedSecureRandom(this);

			try
			{
				keyGen = KeyGenerator.getInstance(alg, "BC");
				keyGen.init(strength, rand);

				key = keyGen.generateKey();

				@in = Cipher.getInstance(alg + "/ECB/PKCS7Padding", "BC");
				@out = Cipher.getInstance(alg + "/ECB/PKCS7Padding", "BC");

				@out.init(Cipher.ENCRYPT_MODE, key, rand);
			}
			catch (Exception e)
			{
				fail(alg + " failed initialisation - " + e.ToString());
			}

			try
			{
				@in.init(Cipher.DECRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail(alg + " failed initialisation - " + e.ToString());
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
				fail(alg + " failed encryption - " + e.ToString());
			}

			byte[] bytes;

			bytes = bOut.toByteArray();

			if (!equalArray(bytes, output))
			{
				fail(alg + " failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
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
				fail(alg + " failed encryption - " + e.ToString());
			}

			if (!equalArray(bytes, input))
			{
				fail(alg + " failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}

			//
			// keyspec test
			//
			try
			{
				SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(alg, "BC");
				DESedeKeySpec keySpec = (DESedeKeySpec)keyFactory.getKeySpec((SecretKey)key, typeof(DESedeKeySpec));

				if (!equalArray(key.getEncoded(), keySpec.getKey(), 16))
				{
					fail(alg + " KeySpec does not match key.");
				}
			}
			catch (Exception e)
			{
				fail(alg + " failed keyspec - " + e.ToString());
			}
		}

		public override void performTest()
		{
			for (int i = 0; i != cipherTests1.Length; i += 2)
			{
				test("DESEDE", int.Parse(cipherTests1[i]), input1, Hex.decode(cipherTests1[i + 1]));
			}

			for (int i = 0; i != cipherTests1.Length; i += 2)
			{
				test("TDEA", int.Parse(cipherTests1[i]), input1, Hex.decode(cipherTests1[i + 1]));
			}

			byte[] kek1 = Hex.decode("255e0d1c07b646dfb3134cc843ba8aa71f025b7c0838251f");
			byte[] iv1 = Hex.decode("5dd4cbfc96f5453b");
			byte[] in1 = Hex.decode("2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98");
			byte[] out1 = Hex.decode("690107618ef092b3b48ca1796b234ae9fa33ebb4159604037db5d6a84eb3aac2768c632775a467d4");

			wrapTest("DESEDE", 1, kek1, iv1, in1, out1);
			wrapTest("TDEA", 1, kek1, iv1, in1, out1);
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new DESedeTest());
		}
	}

}