using org.bouncycastle.asn1.ua;

using System;

namespace org.bouncycastle.jce.provider.test
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using UAObjectIdentifiers = org.bouncycastle.asn1.ua.UAObjectIdentifiers;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// basic test class for DSTU7624
	/// </summary>
	public class DSTU7624Test : BaseBlockCipherTest
	{
		public DSTU7624Test() : base("DSTU7624")
		{
		}

		public virtual void test(string name, byte[] keyBytes, byte[] input, byte[] output)
		{
			Key key;
			Cipher @in, @out;
			CipherInputStream cIn;
			CipherOutputStream cOut;
			ByteArrayInputStream bIn;
			ByteArrayOutputStream bOut;

			key = new SecretKeySpec(keyBytes, name);

			@in = Cipher.getInstance(name + "/ECB/NoPadding", "BC");
			@out = Cipher.getInstance(name + "/ECB/NoPadding", "BC");

			try
			{
				@out.init(Cipher.ENCRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("DSTU7624 failed initialisation - " + e.ToString(), e);
			}

			try
			{
				@in.init(Cipher.DECRYPT_MODE, key);
			}
			catch (Exception e)
			{
				fail("DSTU7624 failed initialisation - " + e.ToString(), e);
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
				fail("DSTU7624 failed encryption - " + e.ToString(), e);
			}

			byte[] bytes;

			bytes = bOut.toByteArray();

			if (!areEqual(bytes, output))
			{
				fail("DSTU7624 failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
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
				fail("DSTU7624 failed encryption - " + e.ToString(), e);
			}

			if (!areEqual(bytes, input))
			{
				fail("DSTU7624 failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}
		}

		public override void performTest()
		{
			test("DSTU7624", Hex.decode("000102030405060708090A0B0C0D0E0F"), Hex.decode("101112131415161718191A1B1C1D1E1F"), Hex.decode("81BF1C7D779BAC20E1C9EA39B4D2AD06"));
			test("DSTU7624", Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"), Hex.decode("202122232425262728292A2B2C2D2E2F"), Hex.decode("58EC3E091000158A1148F7166F334F14"));

			test("DSTU7624-128", Hex.decode("000102030405060708090A0B0C0D0E0F"), Hex.decode("101112131415161718191A1B1C1D1E1F"), Hex.decode("81BF1C7D779BAC20E1C9EA39B4D2AD06"));
			test("DSTU7624-128", Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"), Hex.decode("202122232425262728292A2B2C2D2E2F"), Hex.decode("58EC3E091000158A1148F7166F334F14"));

			test("DSTU7624-256", Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"), Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"), Hex.decode("F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C"));
			test("DSTU7624-256", Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"), Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"), Hex.decode("606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9"));

			test("DSTU7624-512", Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"), Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"), Hex.decode("4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9"));

			byte[] kek1 = Hex.decode("000102030405060708090A0B0C0D0E0F");
			byte[] in1 = Hex.decode("101112131415161718191A1B1C1D1E1F");
			byte[] out1 = Hex.decode("1DC91DC6E52575F6DBED25ADDA95A1B6AD3E15056E489738972C199FB9EE2913");

			wrapTest(1, "DSTU7624Wrap", kek1, in1, out1);

			string[] oids = new string[] {UAObjectIdentifiers_Fields.dstu7624ecb_128.getId(), UAObjectIdentifiers_Fields.dstu7624ecb_256.getId(), UAObjectIdentifiers_Fields.dstu7624ecb_512.getId(), UAObjectIdentifiers_Fields.dstu7624cbc_128.getId(), UAObjectIdentifiers_Fields.dstu7624cbc_256.getId(), UAObjectIdentifiers_Fields.dstu7624cbc_512.getId(), UAObjectIdentifiers_Fields.dstu7624ofb_128.getId(), UAObjectIdentifiers_Fields.dstu7624ofb_256.getId(), UAObjectIdentifiers_Fields.dstu7624ofb_512.getId(), UAObjectIdentifiers_Fields.dstu7624cfb_128.getId(), UAObjectIdentifiers_Fields.dstu7624cfb_256.getId(), UAObjectIdentifiers_Fields.dstu7624cfb_512.getId(), UAObjectIdentifiers_Fields.dstu7624ctr_128.getId(), UAObjectIdentifiers_Fields.dstu7624ctr_256.getId(), UAObjectIdentifiers_Fields.dstu7624ctr_512.getId(), UAObjectIdentifiers_Fields.dstu7624ccm_128.getId(), UAObjectIdentifiers_Fields.dstu7624ccm_256.getId(), UAObjectIdentifiers_Fields.dstu7624ccm_512.getId()};

			string[] names = new string[] {"DSTU7624-128/ECB/PKCS7Padding", "DSTU7624-256/ECB/PKCS7Padding", "DSTU7624-512/ECB/PKCS7Padding", "DSTU7624-128/CBC/PKCS7Padding", "DSTU7624-256/CBC/PKCS7Padding", "DSTU7624-512/CBC/PKCS7Padding", "DSTU7624-128/OFB/NoPadding", "DSTU7624-256/OFB/NoPadding", "DSTU7624-512/OFB/NoPadding", "DSTU7624-128/CFB/NoPadding", "DSTU7624-256/CFB/NoPadding", "DSTU7624-512/CFB/NoPadding", "DSTU7624-128/CTR/NoPadding", "DSTU7624-256/CTR/NoPadding", "DSTU7624-512/CTR/NoPadding", "DSTU7624-128/CCM/NoPadding", "DSTU7624-256/CCM/NoPadding", "DSTU7624-512/CCM/NoPadding"};

			int[] keyBlockLengths = new int[] {16, 32, 64, 16, 32, 64, 16, 32, 64, 16, 32, 64, 16, 32, 64, 16, 32, 64};

			oidTest(oids, names, keyBlockLengths);

			wrapOidTest(UAObjectIdentifiers_Fields.dstu7624kw_128, "DSTU7624Wrap", 16);

			wrapOidTest(UAObjectIdentifiers_Fields.dstu7624kw_256, "DSTU7624-256Wrap", 32);

			wrapOidTest(UAObjectIdentifiers_Fields.dstu7624kw_512, "DSTU7624-512Wrap", 64);

			macOidTest(UAObjectIdentifiers_Fields.dstu7624gmac_128, "DSTU7624GMAC", 16);

			macOidTest(UAObjectIdentifiers_Fields.dstu7624gmac_128, "DSTU7624-128GMAC", 16);

			macOidTest(UAObjectIdentifiers_Fields.dstu7624gmac_256, "DSTU7624-256GMAC", 32);

			macOidTest(UAObjectIdentifiers_Fields.dstu7624gmac_512, "DSTU7624-512GMAC", 64);
		}

		public virtual void wrapOidTest(ASN1ObjectIdentifier oid, string name, int blockLength)
		{
			SecureRandom random = new SecureRandom();

			byte[] data = new byte[blockLength];

			random.nextBytes(data);

			Cipher c1 = Cipher.getInstance(oid.getId(), "BC");
			Cipher c2 = Cipher.getInstance(name, "BC");
			KeyGenerator kg = KeyGenerator.getInstance(oid.getId(), "BC");

			SecretKey k = kg.generateKey();

			c1.init(Cipher.WRAP_MODE, k);
			c2.init(Cipher.UNWRAP_MODE, k);

			Key wKey = c2.unwrap(c1.wrap(new SecretKeySpec(data, algorithm)), algorithm, Cipher.SECRET_KEY);

			if (!areEqual(data, wKey.getEncoded()))
			{
				fail("failed wrap OID test");
			}

			if (k.getEncoded().length != blockLength)
			{
				fail("failed key length test");
			}
		}

		public virtual void macOidTest(ASN1ObjectIdentifier oid, string name, int blockLength)
		{
			SecureRandom random = new SecureRandom();

			byte[] data = new byte[blockLength];

			random.nextBytes(data);

			Mac m1 = Mac.getInstance(oid.getId(), "BC");
			Mac m2 = Mac.getInstance(name, "BC");
			KeyGenerator kg = KeyGenerator.getInstance(oid.getId(), "BC");

			SecretKey k = kg.generateKey();

			m1.init(k, new IvParameterSpec(new byte[blockLength]));
			m2.init(k, new IvParameterSpec(new byte[blockLength]));

			m1.update(data);

			m2.update(data);

			byte[] mac = m1.doFinal();

			if (mac.Length != blockLength)
			{
				fail("mac wrong size");
			}
			if (!areEqual(mac, m2.doFinal()))
			{
				fail("failed mac OID test");
			}

			if (k.getEncoded().length != blockLength)
			{
				fail("failed key length test");
			}
		}

		private override void oidTest(string[] oids, string[] names, int[] keyBlockLengths)
		{
			SecureRandom random = new SecureRandom();

			for (int i = 0; i != oids.Length; i++)
			{
				byte[] data = new byte[keyBlockLengths[i]];

				random.nextBytes(data);

				IvParameterSpec ivSpec = new IvParameterSpec(new byte[keyBlockLengths[i]]);
				Cipher c1 = Cipher.getInstance(oids[i], "BC");
				Cipher c2 = Cipher.getInstance(names[i], "BC");
				KeyGenerator kg = KeyGenerator.getInstance(oids[i], "BC");

				SecretKey k = kg.generateKey();

				if (names[i].IndexOf("/ECB/", StringComparison.Ordinal) > 0)
				{
					c1.init(Cipher.ENCRYPT_MODE, k);
					c2.init(Cipher.DECRYPT_MODE, k);
				}
				else
				{
					c1.init(Cipher.ENCRYPT_MODE, k, ivSpec);
					c2.init(Cipher.DECRYPT_MODE, k, ivSpec);
				}

				byte[] result = c2.doFinal(c1.doFinal(data));

				if (!areEqual(data, result))
				{
					fail("failed OID test: " + names[i]);
				}

				if (k.getEncoded().length != keyBlockLengths[i])
				{
					fail("failed key length test");
				}
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new DSTU7624Test());
		}
	}

}