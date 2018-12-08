using org.bouncycastle.asn1.cryptopro;

using System;

namespace org.bouncycastle.jce.provider.test
{


	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// basic test class for the GOST28147 cipher
	/// </summary>
	public class GOST28147Test : SimpleTest
	{
		internal static string[] cipherTests = new string[] {"256", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "4e6f77206973207468652074696d6520666f7220616c6c20", "281630d0d5770030068c252d841e84149ccc1912052dbc02", "256", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "4e6f77206973207468652074696d65208a920c6ed1a804f5", "88e543dfc04dc4f764fa7b624741cec07de49b007bf36065"};

		public override string getName()
		{
			return "GOST28147";
		}

		public virtual void testECB(int strength, byte[] keyBytes, byte[] input, byte[] output)
		{
			Key key;
			Cipher @in, @out;
			CipherInputStream cIn;
			CipherOutputStream cOut;
			ByteArrayInputStream bIn;
			ByteArrayOutputStream bOut;

			key = new SecretKeySpec(keyBytes, "GOST28147");

			@in = Cipher.getInstance("GOST28147/ECB/NoPadding", "BC");
			@out = Cipher.getInstance("GOST28147/ECB/NoPadding", "BC");
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
				fail("GOST28147 failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
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
				fail("GOST28147 failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}
		}

		public virtual void testCFB(int strength, byte[] keyBytes, byte[] input, byte[] output)
		{
			Key key;
			Cipher @in, @out;
			CipherInputStream cIn;
			CipherOutputStream cOut;
			ByteArrayInputStream bIn;
			ByteArrayOutputStream bOut;

			key = new SecretKeySpec(keyBytes, "GOST28147");

			@in = Cipher.getInstance("GOST28147/CFB8/NoPadding", "BC");
			@out = Cipher.getInstance("GOST28147/CFB8/NoPadding", "BC");
			byte[] iv = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};

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
				fail("GOST28147 failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
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
				fail("GOST28147 failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}
		}

		private void oidTest()
		{
			string[] oids = new string[] {CryptoProObjectIdentifiers_Fields.gostR28147_gcfb.getId()};

			string[] names = new string[] {"GOST28147/GCFB/NoPadding"};

			try
			{

				byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
				IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);

				for (int i = 0; i != oids.Length; i++)
				{
					Cipher c1 = Cipher.getInstance(oids[i], "BC");
					Cipher c2 = Cipher.getInstance(names[i], "BC");
					KeyGenerator kg = KeyGenerator.getInstance(oids[i], "BC");

					SecretKey k = kg.generateKey();

					c1.init(Cipher.ENCRYPT_MODE, k, ivSpec);
					c2.init(Cipher.DECRYPT_MODE, k, ivSpec);

					byte[] result = c2.doFinal(c1.doFinal(data));

					if (!areEqual(data, result))
					{
						fail("failed OID test");
					}
				}
			}
			catch (Exception ex)
			{
				fail("failed exception " + ex.ToString(), ex);
			}
		}

			public override void performTest()
			{
				for (int i = 0; i != cipherTests.Length; i += 8)
				{
					testECB(int.Parse(cipherTests[i]), Hex.decode(cipherTests[i + 1]), Hex.decode(cipherTests[i + 2]), Hex.decode(cipherTests[i + 3]));

					testCFB(int.Parse(cipherTests[i + 4]), Hex.decode(cipherTests[i + 4 + 1]), Hex.decode(cipherTests[i + 4 + 2]), Hex.decode(cipherTests[i + 4 + 3]));

					oidTest();
				}

				Mac mac = Mac.getInstance("GOST28147MAC", "BC");

				mac.init(new SecretKeySpec(Hex.decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), "GOST28147"));

				if (!Arrays.areEqual(Hex.decode("1b69996e"), mac.doFinal(Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20"))))
				{
					fail("mac test failed.");
				}
			}

			public static void Main(string[] args)
			{
				Security.addProvider(new BouncyCastleProvider());

				runTest(new GOST28147Test());
			}
	}

}