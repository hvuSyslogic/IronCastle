using org.bouncycastle.asn1.nsri;

using System;

namespace org.bouncycastle.jce.provider.test
{


	using NSRIObjectIdentifiers = org.bouncycastle.asn1.nsri.NSRIObjectIdentifiers;
	using FixedSecureRandom = org.bouncycastle.crypto.prng.FixedSecureRandom;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// basic test class for the ARIA cipher vectors from FIPS-197
	/// </summary>
	public class ARIATest : BaseBlockCipherTest
	{
		internal static string[] cipherTests = new string[] {"128", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "d718fbd6ab644c739da95f3be6451778", "192", "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "26449c1805dbe7aa25a468ce263a9e79", "256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "f92bd7c79fb72e2f2b8f80c1972d24fc"};

		public ARIATest() : base("ARIA")
		{
		}

		private void test(int strength, byte[] keyBytes, byte[] input, byte[] output)
		{
			Key key;
			Cipher @in, @out;
			CipherInputStream cIn;
			CipherOutputStream cOut;
			ByteArrayInputStream bIn;
			ByteArrayOutputStream bOut;

			key = new SecretKeySpec(keyBytes, "ARIA");

			@in = Cipher.getInstance("ARIA/ECB/NoPadding", "BC");
			@out = Cipher.getInstance("ARIA/ECB/NoPadding", "BC");

			try
			{
				@out.init(Cipher.ENCRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("ARIA failed initialisation - " + e.ToString(), e);
			}

			try
			{
				@in.init(Cipher.DECRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("ARIA failed initialisation - " + e.ToString(), e);
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
				fail("ARIA failed encryption - " + e.ToString(), e);
			}

			byte[] bytes;

			bytes = bOut.toByteArray();

			if (!areEqual(bytes, output))
			{
				fail("ARIA failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
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
				fail("ARIA failed encryption - " + e.ToString(), e);
			}

			if (!areEqual(bytes, input))
			{
				fail("ARIA failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}
		}

		private void eaxTest()
		{
			byte[] K = Hex.decode("233952DEE4D5ED5F9B9C6D6FF80FF478");
			byte[] N = Hex.decode("62EC67F9C3A4A407FCB2A8C49031A8B3");
			byte[] P = Hex.decode("68656c6c6f20776f726c642121");
			byte[] C = Hex.decode("85fe63d6cfb872d2420e65425c074dfad6fe752e03");

			Key key;
			Cipher @in, @out;

			key = new SecretKeySpec(K, "ARIA");

			@in = Cipher.getInstance("ARIA/EAX/NoPadding", "BC");
			@out = Cipher.getInstance("ARIA/EAX/NoPadding", "BC");

			@in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

			byte[] enc = @in.doFinal(P);
			if (!areEqual(enc, C))
			{
				fail("ciphertext doesn't match in EAX: " + Hex.toHexString(enc));
			}

			@out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

			byte[] dec = @out.doFinal(C);
			if (!areEqual(dec, P))
			{
				fail("plaintext doesn't match in EAX");
			}

			try
			{
				@in = Cipher.getInstance("ARIA/EAX/PKCS5Padding", "BC");

				fail("bad padding missed in EAX");
			}
			catch (NoSuchPaddingException)
			{
				// expected
			}
		}

		private void ccmTest()
		{
			byte[] K = Hex.decode("404142434445464748494a4b4c4d4e4f");
			byte[] N = Hex.decode("10111213141516");
			byte[] P = Hex.decode("68656c6c6f20776f726c642121");
			byte[] C = Hex.decode("0af625ff69cd9dbe65fae181d654717eb7a0263bcd");

			Key key;
			Cipher @in, @out;

			key = new SecretKeySpec(K, "ARIA");

			@in = Cipher.getInstance("ARIA/CCM/NoPadding", "BC");
			@out = Cipher.getInstance("ARIA/CCM/NoPadding", "BC");

			@in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

			byte[] enc = @in.doFinal(P);
			if (!areEqual(enc, C))
			{
				fail("ciphertext doesn't match in CCM: " + Hex.toHexString(enc));
			}

			@out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

			byte[] dec = @out.doFinal(C);
			if (!areEqual(dec, P))
			{
				fail("plaintext doesn't match in CCM");
			}

			try
			{
				@in = Cipher.getInstance("ARIA/CCM/PKCS5Padding", "BC");

				fail("bad padding missed in CCM");
			}
			catch (NoSuchPaddingException)
			{
				// expected
			}
		}

		private void gcmTest()
		{
			// Test Case 15 from McGrew/Viega
			byte[] K = Hex.decode("feffe9928665731c6d6a8f9467308308" + "feffe9928665731c6d6a8f9467308308");
			byte[] P = Hex.decode("d9313225f88406e5a55909c5aff5269a" + "86a7a9531534f7da2e4c303d8a318a72" + "1c3c0c95956809532fcf0e2449a6b525" + "b16aedf5aa0de657ba637b391aafd255");
			byte[] N = Hex.decode("cafebabefacedbaddecaf888");
			string T = "c8f245c8619ca9ba7d6d9545e7f48214";
			byte[] C = Hex.decode("c3aa0e01a4f8b5dfdb25d0f1c78c275e516114080e2be7a7f7bffd4504b19a8552f80ad5b55f3d911725489629996d398d5ed6f077e22924c5b8ebe20a219693" + T);

			Key key;
			Cipher @in, @out;

			key = new SecretKeySpec(K, "ARIA");

			@in = Cipher.getInstance("ARIA/GCM/NoPadding", "BC");
			@out = Cipher.getInstance("ARIA/GCM/NoPadding", "BC");

			@in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

			byte[] enc = @in.doFinal(P);
			if (!areEqual(enc, C))
			{
				fail("ciphertext doesn't match in GCM: " + Hex.toHexString(enc));
			}

			@out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

			byte[] dec = @out.doFinal(C);
			if (!areEqual(dec, P))
			{
				fail("plaintext doesn't match in GCM");
			}

			try
			{
				@in = Cipher.getInstance("ARIA/GCM/PKCS5Padding", "BC");

				fail("bad padding missed in GCM");
			}
			catch (NoSuchPaddingException)
			{
				// expected
			}
		}

		private void ocbTest()
		{
			byte[] K = Hex.decode("000102030405060708090A0B0C0D0E0F");
			byte[] P = Hex.decode("000102030405060708090A0B0C0D0E0F");
			byte[] N = Hex.decode("000102030405060708090A0B");
			string T = "0027ce4f3aaeec75";
			byte[] C = Hex.decode("7bcae9eac9f1f54704a630e309099a87f53a1c1559de1b3b" + T);

			Key key;
			Cipher @in, @out;

			key = new SecretKeySpec(K, "ARIA");

			@in = Cipher.getInstance("ARIA/OCB/NoPadding", "BC");
			@out = Cipher.getInstance("ARIA/OCB/NoPadding", "BC");

			@in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

			byte[] enc = @in.doFinal(P);
			if (!areEqual(enc, C))
			{
				fail("ciphertext doesn't match in OCB: " + Hex.toHexString(enc));
			}

			@out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

			byte[] dec = @out.doFinal(C);
			if (!areEqual(dec, P))
			{
				fail("plaintext doesn't match in OCB");
			}

			try
			{
				@in = Cipher.getInstance("ARIA/OCB/PKCS5Padding", "BC");

				fail("bad padding missed in OCB");
			}
			catch (NoSuchPaddingException)
			{
				// expected
			}
		}

		public override void performTest()
		{
			for (int i = 0; i != cipherTests.Length; i += 4)
			{
				test(int.Parse(cipherTests[i]), Hex.decode(cipherTests[i + 1]), Hex.decode(cipherTests[i + 2]), Hex.decode(cipherTests[i + 3]));
			}

			byte[] kek1 = Hex.decode("000102030405060708090a0b0c0d0e0f");
			byte[] in1 = Hex.decode("00112233445566778899aabbccddeeff");
			byte[] out1 = Hex.decode("a93f148d4909d85f1aae656909879275ae597b3acf9d60db");

			wrapTest(1, "ARIAWrap", kek1, in1, out1);

			byte[] kek2 = Hex.decode("000102030405060708090a0b0c0d0e0f");
			byte[] in2 = Hex.decode("00112233445566778899aabbccddeeff");
			byte[] out2 = Hex.decode("9b2d3cac0acf9d4bde7c1bdb0313fbef931f025acc77bf57d3d1cabc88b514d0");

			wrapTest(2, "ARIARFC3211WRAP", kek2, kek2, new FixedSecureRandom(Hex.decode("9688df2af1b7b1ac9688df2a")), in2, out2);

			byte[] kek3 = Hex.decode("000102030405060708090a0b0c0d0e0f");
			byte[] in3 = Hex.decode("00112233445566778899aabbccddeeff");
			byte[] out3 = Hex.decode("ac0e22699a036ced63adeb75f4946f82dc98ad8af43b24d5");

			wrapTest(3, "ARIAWrapPad", kek3, in3, out3);

			string[] oids = new string[] {NSRIObjectIdentifiers_Fields.id_aria128_ecb.getId(), NSRIObjectIdentifiers_Fields.id_aria128_cbc.getId(), NSRIObjectIdentifiers_Fields.id_aria128_ofb.getId(), NSRIObjectIdentifiers_Fields.id_aria128_cfb.getId(), NSRIObjectIdentifiers_Fields.id_aria192_ecb.getId(), NSRIObjectIdentifiers_Fields.id_aria192_cbc.getId(), NSRIObjectIdentifiers_Fields.id_aria192_ofb.getId(), NSRIObjectIdentifiers_Fields.id_aria192_cfb.getId(), NSRIObjectIdentifiers_Fields.id_aria256_ecb.getId(), NSRIObjectIdentifiers_Fields.id_aria256_cbc.getId(), NSRIObjectIdentifiers_Fields.id_aria256_ofb.getId(), NSRIObjectIdentifiers_Fields.id_aria256_cfb.getId()};

			string[] names = new string[] {"ARIA/ECB/PKCS7Padding", "ARIA/CBC/PKCS7Padding", "ARIA/OFB/NoPadding", "ARIA/CFB/NoPadding", "ARIA/ECB/PKCS7Padding", "ARIA/CBC/PKCS7Padding", "ARIA/OFB/NoPadding", "ARIA/CFB/NoPadding", "ARIA/ECB/PKCS7Padding", "ARIA/CBC/PKCS7Padding", "ARIA/OFB/NoPadding", "ARIA/CFB/NoPadding"};

			oidTest(oids, names, 4);


			string[] wrapOids = new string[] {NSRIObjectIdentifiers_Fields.id_aria128_kw.getId(), NSRIObjectIdentifiers_Fields.id_aria192_kw.getId(), NSRIObjectIdentifiers_Fields.id_aria256_kw.getId()};

			wrapOidTest(wrapOids, "ARIAWrap");

			wrapOids = new string[] {NSRIObjectIdentifiers_Fields.id_aria128_kwp.getId(), NSRIObjectIdentifiers_Fields.id_aria192_kwp.getId(), NSRIObjectIdentifiers_Fields.id_aria256_kwp.getId()};

			wrapOidTest(wrapOids, "ARIAWrapPad");

			eaxTest();
			ccmTest();
			gcmTest();
			ocbTest();
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new ARIATest());
		}
	}

}