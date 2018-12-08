namespace org.bouncycastle.jce.provider.test
{


	using ECDHBasicAgreement = org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using IESEngine = org.bouncycastle.crypto.engines.IESEngine;
	using KDF2BytesGenerator = org.bouncycastle.crypto.generators.KDF2BytesGenerator;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using IESCipher = org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
	using ECPrivateKey = org.bouncycastle.jce.interfaces.ECPrivateKey;
	using ECPublicKey = org.bouncycastle.jce.interfaces.ECPublicKey;
	using IESParameterSpec = org.bouncycastle.jce.spec.IESParameterSpec;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// Test for ECIES - Elliptic Curve Integrated Encryption Scheme
	/// </summary>
	public class ECIESTest : SimpleTest
	{

		public ECIESTest()
		{
		}

		public override string getName()
		{
			return "ECIES";
		}

		public override void performTest()
		{
			byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
			byte[] encoding = Hex.decode("303132333435363738393a3b3c3d3e3f");


			IESCipher c1 = new IESCipher.ECIES();
			IESCipher c2 = new IESCipher.ECIES();
			IESParameterSpec @params = new IESParameterSpec(derivation,encoding,128);

			// Testing ECIES with default curve in streaming mode
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
			doTest("ECIES with default", g, "ECIES", @params);

			// Testing ECIES with 192-bit curve in streaming mode 
			g.initialize(192, new SecureRandom());
			doTest("ECIES with 192-bit", g, "ECIES", @params);

			// Testing ECIES with 256-bit curve in streaming mode 
			g.initialize(256, new SecureRandom());
			doTest("ECIES with 256-bit", g, "ECIES", @params);


			c1 = new IESCipher(new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()), new PaddedBufferedBlockCipher(new DESEngine())));

			c2 = new IESCipher(new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()), new PaddedBufferedBlockCipher(new DESEngine())));

			@params = new IESParameterSpec(derivation, encoding, 128, 128, Hex.decode("0001020304050607"));

			// Testing ECIES with default curve using DES
			g = KeyPairGenerator.getInstance("EC", "BC");

			// Testing ECIES with 256-bit curve using DES-CBC
			g.initialize(256, new SecureRandom());
			doTest("256-bit", g, "ECIESwithDESEDE-CBC", @params);

			@params = new IESParameterSpec(derivation, encoding, 128, 128, Hex.decode("0001020304050607"));
			g.initialize(256, new SecureRandom());
			doTest("256-bit", g, "ECIESwithDESEDE-CBC", @params);

			try
			{
				@params = new IESParameterSpec(derivation, encoding, 128, 128, new byte[10]);
				g.initialize(256, new SecureRandom());
				doTest("256-bit", g, "ECIESwithDESEDE-CBC", @params);
				fail("DESEDE no exception!");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				if (!e.Message.Equals("NONCE in IES Parameters needs to be 8 bytes long"))
				{
					fail("DESEDE wrong message!");
				}
			}

			c1 = new IESCipher.ECIESwithAESCBC();
			c2 = new IESCipher.ECIESwithAESCBC();
			@params = new IESParameterSpec(derivation, encoding, 128, 128, Hex.decode("000102030405060708090a0b0c0d0e0f"));

			// Testing ECIES with 256-bit curve using AES-CBC
			g.initialize(256, new SecureRandom());
			doTest("256-bit", g, "ECIESwithAES-CBC", @params);

			@params = new IESParameterSpec(derivation, encoding, 128, 128, Hex.decode("000102030405060708090a0b0c0d0e0f"));
			g.initialize(256, new SecureRandom());
			doTest("256-bit", g, "ECIESwithAES-CBC", @params);

			try
			{
				@params = new IESParameterSpec(derivation, encoding, 128, 128, new byte[10]);
				g.initialize(256, new SecureRandom());
				doTest("256-bit", g, "ECIESwithAES-CBC", @params);
				fail("AES no exception!");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				if (!e.Message.Equals("NONCE in IES Parameters needs to be 16 bytes long"))
				{
					fail("AES wrong message!");
				}
			}

			KeyPair keyPair = g.generateKeyPair();
			ECPublicKey pub = (ECPublicKey)keyPair.getPublic();
			ECPrivateKey priv = (ECPrivateKey)keyPair.getPrivate();

			Cipher c = Cipher.getInstance("ECIESwithAES-CBC", "BC");

			try
			{
				c.init(Cipher.ENCRYPT_MODE, pub, new IESParameterSpec(derivation, encoding, 128, 128, null));

				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isTrue("message ", "NONCE in IES Parameters needs to be 16 bytes long".Equals(e.Message));
			}

			try
			{
				c.init(Cipher.DECRYPT_MODE, priv);

				fail("no exception");
			}
			catch (IllegalArgumentException e)
			{
				isTrue("message ", "cannot handle supplied parameter spec: NONCE in IES Parameters needs to be 16 bytes long".Equals(e.Message));
			}

			try
			{
				c.init(Cipher.DECRYPT_MODE, priv, new IESParameterSpec(derivation, encoding, 128, 128, null));

				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isTrue("message ", "NONCE in IES Parameters needs to be 16 bytes long".Equals(e.Message));
			}

			sealedObjectTest();
		}

		private void sealedObjectTest()
		{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECIES");
			kpg.initialize(new ECGenParameterSpec("secp256r1"));
			KeyPair keyPair = kpg.generateKeyPair();

			Cipher cipher = Cipher.getInstance("ECIES");
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

			string toEncrypt = "Hello";

			// Check that cipher works ok
			cipher.doFinal(toEncrypt.GetBytes());

			// Using a SealedObject to encrypt the same string fails with a NullPointerException
			SealedObject sealedObject = new SealedObject(toEncrypt, cipher);

			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

			string result = (string)sealedObject.getObject(cipher);

			isTrue("result wrong", result.Equals(toEncrypt));

			result = (string)sealedObject.getObject(keyPair.getPrivate());

			isTrue("result wrong", result.Equals(toEncrypt));
		}

		public virtual void doTest(string testname, KeyPairGenerator g, string cipher, IESParameterSpec p)
		{

			byte[] message = Hex.decode("0102030405060708090a0b0c0d0e0f10111213141516");
			byte[] out1, out2;

			// Generate static key pair
			KeyPair KeyPair = g.generateKeyPair();
			ECPublicKey Pub = (ECPublicKey) KeyPair.getPublic();
			ECPrivateKey Priv = (ECPrivateKey) KeyPair.getPrivate();

			Cipher c1 = Cipher.getInstance(cipher);
			Cipher c2 = Cipher.getInstance(cipher);

			// Testing with null parameters and DHAES mode off
			c1.init(Cipher.ENCRYPT_MODE, Pub, new SecureRandom());
			c2.init(Cipher.DECRYPT_MODE, Priv, c1.getParameters());

			isTrue("nonce mismatch", Arrays.areEqual(c1.getIV(), c2.getIV()));

			out1 = c1.doFinal(message, 0, message.Length);
			out2 = c2.doFinal(out1, 0, out1.Length);
			if (!areEqual(out2, message))
			{
				fail(testname + " test failed with null parameters, DHAES mode false.");
			}


			// Testing with given parameters and DHAES mode off
			c1.init(Cipher.ENCRYPT_MODE, Pub, p, new SecureRandom());
			c2.init(Cipher.DECRYPT_MODE, Priv, p);
			out1 = c1.doFinal(message, 0, message.Length);
			out2 = c2.doFinal(out1, 0, out1.Length);
			if (!areEqual(out2, message))
			{
				fail(testname + " test failed with non-null parameters, DHAES mode false.");
			}

			//
			// corrupted data test
			//
			int offset = out1.Length - (message.Length + 8);
			byte[] tmp = new byte[out1.Length];
			for (int i = offset; i != out1.Length; i++)
			{
				JavaSystem.arraycopy(out1, 0, tmp, 0, tmp.Length);
				tmp[i] = (byte)~tmp[i];

				try
				{
					c2.doFinal(tmp, 0, tmp.Length);

					fail("decrypted corrupted data");
				}
				catch (BadPaddingException e)
				{
					isTrue("wrong message: " + e.Message, "unable to process block".Equals(e.Message));
				}
			}
	// TODO: DHAES mode is not currently implemented, perhaps it shouldn't be...
	//        c1 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding","BC");
	//        c2 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding","BC");
	//
	//        // Testing with null parameters and DHAES mode on
	//        c1.init(Cipher.ENCRYPT_MODE, Pub, new SecureRandom());
	//        c2.init(Cipher.DECRYPT_MODE, Priv, new SecureRandom());
	//
	//        out1 = c1.doFinal(message, 0, message.length);
	//        out2 = c2.doFinal(out1, 0, out1.length);
	//        if (!areEqual(out2, message))
	//            fail(testname + " test failed with null parameters, DHAES mode true.");
	//
	//        c1 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding");
	//        c2 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding");
	//
	//        // Testing with given parameters and DHAES mode on
	//        c1.init(Cipher.ENCRYPT_MODE, Pub, p, new SecureRandom());
	//        c2.init(Cipher.DECRYPT_MODE, Priv, p, new SecureRandom());
	//
	//        out1 = c1.doFinal(message, 0, message.length);
	//        out2 = c2.doFinal(out1, 0, out1.length);
	//        if (!areEqual(out2, message))
	//            fail(testname + " test failed with non-null parameters, DHAES mode true.");

		}



		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new ECIESTest());
		}
	}

}