using System;

namespace org.bouncycastle.jce.provider.test
{


	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// basic test class for the Shacal2 cipher, vector from NESSIE (Test vectors set 8, vector# 0)
	/// </summary>
	public class Shacal2Test : SimpleTest
	{
		internal static string[] cipherTests = new string[] {"512", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", "98BCC10405AB0BFC686BECECAAD01AC19B452511BCEB9CB094F905C51CA45430", "00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0F"};

		public override string getName()
		{
			return "Shacal2";
		}

		private const int KEY_SIZE_BITS = 512;

		private static readonly byte[] TEST_BYTES = new byte[1536];

		private static readonly char[] TEST_PASSWORD = new char[1536];

		static Shacal2Test()
		{
			(new SecureRandom()).nextBytes(TEST_BYTES);
			int total = TEST_PASSWORD.Length;
			for (char c = 'A'; c <= 'Z' && total > 0; TEST_PASSWORD[TEST_PASSWORD.Length - total] = c, c++, total--)
			{
				;
			}
		}

		private void blockTest()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] salt = new byte[KEY_SIZE_BITS / 8];
			byte[] salt = new byte[KEY_SIZE_BITS / 8];
			(new SecureRandom()).nextBytes(salt);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.spec.KeySpec keySpec = new javax.crypto.spec.PBEKeySpec(TEST_PASSWORD, salt, 262144, KEY_SIZE_BITS);
			KeySpec keySpec = new PBEKeySpec(TEST_PASSWORD, salt, 262144, KEY_SIZE_BITS);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(javax.crypto.SecretKeyFactory.getInstance("PBKDF2", "BC").generateSecret(keySpec).getEncoded(), "Shacal2");
			SecretKey secretKey = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2", "BC").generateSecret(keySpec).getEncoded(), "Shacal2");

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("Shacal2/CBC/ISO10126Padding", "BC");
			Cipher cipher = Cipher.getInstance("Shacal2/CBC/ISO10126Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] iv = cipher.getIV();
			byte[] iv = cipher.getIV();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] ciphertext = cipher.doFinal(TEST_BYTES);
			byte[] ciphertext = cipher.doFinal(TEST_BYTES);

			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] cleartext = cipher.doFinal(ciphertext);
			byte[] cleartext = cipher.doFinal(ciphertext);

			if (!Arrays.areEqual(TEST_BYTES, cleartext))
			{
				fail("Invalid cleartext.");
			}
		}

		public virtual void testECB(int strength, byte[] keyBytes, byte[] input, byte[] output)
		{
			Key key;
			Cipher @in, @out;
			CipherInputStream cIn;
			CipherOutputStream cOut;
			ByteArrayInputStream bIn;
			ByteArrayOutputStream bOut;

			key = new SecretKeySpec(keyBytes, "Shacal2");

			@in = Cipher.getInstance("Shacal2/ECB/NoPadding", "BC");
			@out = Cipher.getInstance("Shacal2/ECB/NoPadding", "BC");
			try
			{
				@out.init(Cipher.ENCRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("Shacal2 failed initialisation - " + e.ToString(), e);
			}

			try
			{
				@in.init(Cipher.DECRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("Shacal2 failed initialisation - " + e.ToString(), e);
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
				fail("Shacal2 failed encryption - " + e.ToString(), e);
			}

			byte[] bytes;

			bytes = bOut.toByteArray();

			if (!areEqual(bytes, output))
			{
				fail("Shacal2 failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
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
				fail("Shacal2 failed encryption - " + e.ToString(), e);
			}

			if (!areEqual(bytes, input))
			{
				fail("Shacal2 failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}
		}

		public override void performTest()
		{
			for (int i = 0; i != cipherTests.Length; i += 4)
			{
				testECB(int.Parse(cipherTests[i]), Hex.decode(cipherTests[i + 1]), Hex.decode(cipherTests[i + 2]), Hex.decode(cipherTests[i + 3]));
			}

			blockTest();
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new Shacal2Test());
		}
	}

}