using org.bouncycastle.asn1.kisa;

using System;

namespace org.bouncycastle.jce.provider.test
{
	using KISAObjectIdentifiers = org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
	using Hex = org.bouncycastle.util.encoders.Hex;


	/// <summary>
	/// basic test class for SEED
	/// </summary>
	public class SEEDTest : BaseBlockCipherTest
	{
		internal static string[] cipherTests = new string[] {"128", "28DBC3BC49FFD87DCFA509B11D422BE7", "B41E6BE2EBA84A148E2EED84593C5EC7", "9B9B7BFCD1813CB95D0B3618F40F5122"};

		public SEEDTest() : base("SEED")
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

			key = new SecretKeySpec(keyBytes, "SEED");

			@in = Cipher.getInstance("SEED/ECB/NoPadding", "BC");
			@out = Cipher.getInstance("SEED/ECB/NoPadding", "BC");

			try
			{
				@out.init(Cipher.ENCRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("SEED failed initialisation - " + e.ToString(), e);
			}

			try
			{
				@in.init(Cipher.DECRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("SEED failed initialisation - " + e.ToString(), e);
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
				fail("SEED failed encryption - " + e.ToString(), e);
			}

			byte[] bytes;

			bytes = bOut.toByteArray();

			if (!areEqual(bytes, output))
			{
				fail("SEED failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
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
				fail("SEED failed encryption - " + e.ToString(), e);
			}

			if (!areEqual(bytes, input))
			{
				fail("SEED failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
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
			byte[] out1 = Hex.decode("bf71f77138b5afea05232a8dad54024e812dc8dd7d132559");

			wrapTest(1, "SEEDWrap", kek1, in1, out1);

			string[] oids = new string[] {KISAObjectIdentifiers_Fields.id_seedCBC.getId()};

			string[] names = new string[] {"SEED/CBC/PKCS7Padding"};

			oidTest(oids, names, 1);

			string[] wrapOids = new string[] {KISAObjectIdentifiers_Fields.id_npki_app_cmsSeed_wrap.getId()};

			wrapOidTest(wrapOids, "SEEDWrap");
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new SEEDTest());
		}
	}

}