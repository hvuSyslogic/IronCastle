using org.bouncycastle.asn1.bc;

using System;

namespace org.bouncycastle.jce.provider.test
{


	using BCObjectIdentifiers = org.bouncycastle.asn1.bc.BCObjectIdentifiers;
	using Digest = org.bouncycastle.crypto.Digest;
	using PBEParametersGenerator = org.bouncycastle.crypto.PBEParametersGenerator;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using OpenSSLPBEParametersGenerator = org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
	using PKCS12ParametersGenerator = org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using PKCS12Key = org.bouncycastle.jcajce.PKCS12Key;
	using PKCS12KeyWithParameters = org.bouncycastle.jcajce.PKCS12KeyWithParameters;
	using BCPBEKey = org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// test out the various PBE modes, making sure the JCE implementations
	/// are compatible woth the light weight ones.
	/// </summary>
	public class PBETest : SimpleTest
	{
		private bool InstanceFieldsInitialized = false;

		public PBETest()
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
		}

		private void InitializeInstanceFields()
		{
			pkcs12Tests = new PKCS12Test[]
			{
				new PKCS12Test(this, "DESede", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC", new SHA1Digest(), 192, 64),
				new PKCS12Test(this, "DESede", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC", new SHA1Digest(), 128, 64),
				new PKCS12Test(this, "RC4", "PBEWITHSHAAND128BITRC4", new SHA1Digest(), 128, 0),
				new PKCS12Test(this, "RC4", "PBEWITHSHAAND40BITRC4", new SHA1Digest(), 40, 0),
				new PKCS12Test(this, "RC2", "PBEWITHSHAAND128BITRC2-CBC", new SHA1Digest(), 128, 64),
				new PKCS12Test(this, "RC2", "PBEWITHSHAAND40BITRC2-CBC", new SHA1Digest(), 40, 64),
				new PKCS12Test(this, "AES", "PBEWithSHA1And128BitAES-CBC-BC", new SHA1Digest(), 128, 128),
				new PKCS12Test(this, "AES", "PBEWithSHA1And192BitAES-CBC-BC", new SHA1Digest(), 192, 128),
				new PKCS12Test(this, "AES", "PBEWithSHA1And256BitAES-CBC-BC", new SHA1Digest(), 256, 128),
				new PKCS12Test(this, "AES", "PBEWithSHA256And128BitAES-CBC-BC", new SHA256Digest(), 128, 128),
				new PKCS12Test(this, "AES", "PBEWithSHA256And192BitAES-CBC-BC", new SHA256Digest(), 192, 128),
				new PKCS12Test(this, "AES", "PBEWithSHA256And256BitAES-CBC-BC", new SHA256Digest(), 256, 128),
				new PKCS12Test(this, "Twofish","PBEWithSHAAndTwofish-CBC", new SHA1Digest(), 256, 128),
				new PKCS12Test(this, "IDEA", "PBEWithSHAAndIDEA-CBC", new SHA1Digest(), 128, 64),
				new PKCS12Test(this, "AES", BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes128_cbc.getId(), new SHA1Digest(), 128, 128),
				new PKCS12Test(this, "AES", BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes192_cbc.getId(), new SHA1Digest(), 192, 128),
				new PKCS12Test(this, "AES", BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes256_cbc.getId(), new SHA1Digest(), 256, 128),
				new PKCS12Test(this, "AES", BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes128_cbc.getId(), new SHA256Digest(), 128, 128),
				new PKCS12Test(this, "AES", BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes192_cbc.getId(), new SHA256Digest(), 192, 128),
				new PKCS12Test(this, "AES", BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes256_cbc.getId(), new SHA256Digest(), 256, 128)
			};
			openSSLTests = new OpenSSLTest[]
			{
				new OpenSSLTest(this, "AES", "PBEWITHMD5AND128BITAES-CBC-OPENSSL", 128, 128),
				new OpenSSLTest(this, "AES", "PBEWITHMD5AND192BITAES-CBC-OPENSSL", 192, 128),
				new OpenSSLTest(this, "AES", "PBEWITHMD5AND256BITAES-CBC-OPENSSL", 256, 128)
			};
		}

		public class OpenSSLTest : SimpleTest
		{
			private readonly PBETest outerInstance;

			internal char[] password;
			internal string baseAlgorithm;
			internal string algorithm;
			internal int keySize;
			internal int ivSize;

			public OpenSSLTest(PBETest outerInstance, string baseAlgorithm, string algorithm, int keySize, int ivSize)
			{
				this.outerInstance = outerInstance;
				this.password = algorithm.ToCharArray();
				this.baseAlgorithm = baseAlgorithm;
				this.algorithm = algorithm;
				this.keySize = keySize;
				this.ivSize = ivSize;
			}

			public override string getName()
			{
				return "OpenSSLPBE";
			}

			public override void performTest()
			{
				byte[] salt = new byte[16];
				int iCount = 100;

				for (int i = 0; i != salt.Length; i++)
				{
					salt[i] = (byte)i;
				}

				OpenSSLPBEParametersGenerator pGen = new OpenSSLPBEParametersGenerator();

				pGen.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt, iCount);

				ParametersWithIV @params = (ParametersWithIV)pGen.generateDerivedParameters(keySize, ivSize);

				SecretKeySpec encKey = new SecretKeySpec(((KeyParameter)@params.getParameters()).getKey(), baseAlgorithm);

				Cipher c;

				if (baseAlgorithm.Equals("RC4"))
				{
					c = Cipher.getInstance(baseAlgorithm, "BC");

					c.init(Cipher.ENCRYPT_MODE, encKey);
				}
				else
				{
					c = Cipher.getInstance(baseAlgorithm + "/CBC/PKCS7Padding", "BC");

					c.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(@params.getIV()));
				}

				byte[] enc = c.doFinal(salt);

				c = Cipher.getInstance(algorithm, "BC");

				PBEKeySpec keySpec = new PBEKeySpec(password, salt, iCount);
				SecretKeyFactory fact = SecretKeyFactory.getInstance(algorithm, "BC");

				c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec));

				byte[] dec = c.doFinal(enc);

				if (!Arrays.areEqual(salt, dec))
				{
					fail("" + algorithm + "failed encryption/decryption test");
				}
			}
		}

		public class PKCS12Test : SimpleTest
		{
			private readonly PBETest outerInstance;

			internal char[] password;
			internal string baseAlgorithm;
			internal string algorithm;
			internal Digest digest;
			internal int keySize;
			internal int ivSize;

			public PKCS12Test(PBETest outerInstance, string baseAlgorithm, string algorithm, Digest digest, int keySize, int ivSize)
			{
				this.outerInstance = outerInstance;
				this.password = algorithm.ToCharArray();
				this.baseAlgorithm = baseAlgorithm;
				this.algorithm = algorithm;
				this.digest = digest;
				this.keySize = keySize;
				this.ivSize = ivSize;
			}

			public override string getName()
			{
				return "PKCS12PBE";
			}

			public override void performTest()
			{
				byte[] salt = new byte[digest.getDigestSize()];
				int iCount = 100;

				digest.doFinal(salt, 0);

				PKCS12ParametersGenerator pGen = new PKCS12ParametersGenerator(digest);

				pGen.init(PBEParametersGenerator.PKCS12PasswordToBytes(password), salt, iCount);

				ParametersWithIV @params = (ParametersWithIV)pGen.generateDerivedParameters(keySize, ivSize);

				SecretKeySpec encKey = new SecretKeySpec(((KeyParameter)@params.getParameters()).getKey(), baseAlgorithm);

				Cipher c;

				if (baseAlgorithm.Equals("RC4"))
				{
					c = Cipher.getInstance(baseAlgorithm, "BC");

					c.init(Cipher.ENCRYPT_MODE, encKey);
				}
				else
				{
					c = Cipher.getInstance(baseAlgorithm + "/CBC/PKCS7Padding", "BC");

					c.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(@params.getIV()));
				}

				byte[] enc = c.doFinal(salt);

				c = Cipher.getInstance(algorithm, "BC");

				PBEKeySpec keySpec = new PBEKeySpec(password, salt, iCount);
				SecretKeyFactory fact = SecretKeyFactory.getInstance(algorithm, "BC");

				c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec));

				byte[] dec = c.doFinal(enc);

				if (!Arrays.areEqual(salt, dec))
				{
					fail("" + algorithm + "failed encryption/decryption test");
				}

				//
				// get the parameters
				//
				AlgorithmParameters param = checkParameters(c, salt, iCount);

				//
				// try using parameters
				//
				c = Cipher.getInstance(algorithm, "BC");

				keySpec = new PBEKeySpec(password);

				c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec), param);

				checkParameters(c, salt, iCount);

				dec = c.doFinal(enc);

				if (!Arrays.areEqual(salt, dec))
				{
					fail("" + algorithm + "failed encryption/decryption test");
				}

				//
				// try using PBESpec
				//
				c = Cipher.getInstance(algorithm, "BC");

				keySpec = new PBEKeySpec(password);

				c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec), param.getParameterSpec(typeof(PBEParameterSpec)));

				checkParameters(c, salt, iCount);

				dec = c.doFinal(enc);

				if (!Arrays.areEqual(salt, dec))
				{
					fail("" + algorithm + "failed encryption/decryption test");
				}
			}

			public virtual AlgorithmParameters checkParameters(Cipher c, byte[] salt, int iCount)
			{
				AlgorithmParameters param = c.getParameters();
				PBEParameterSpec spec = (PBEParameterSpec)param.getParameterSpec(typeof(PBEParameterSpec));

				if (!Arrays.areEqual(salt, spec.getSalt()))
				{
					fail("" + algorithm + "failed salt test");
				}

				if (iCount != spec.getIterationCount())
				{
					fail("" + algorithm + "failed count test");
				}
				return param;
			}
		}

		private PKCS12Test[] pkcs12Tests;

		private OpenSSLTest[] openSSLTests;

		internal static byte[] message = Hex.decode("4869205468657265");

		private byte[] hMac1 = Hex.decode("bcc42174ccb04f425d9a5c8c4a95d6fd7c372911");
		private byte[] hMac2 = Hex.decode("cb1d8bdb6aca9e3fa8980d6eb41ab28a7eb2cfd6");
		private byte[] hMac3 = Hex.decode("514aa173a302c770689269aac08eb8698e5879ac");

		private Cipher makePBECipherUsingParam(string algorithm, int mode, char[] password, byte[] salt, int iterationCount)
		{
			PBEKeySpec pbeSpec = new PBEKeySpec(password);
			SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm, "BC");
			PBEParameterSpec defParams = new PBEParameterSpec(salt, iterationCount);

			Cipher cipher = Cipher.getInstance(algorithm, "BC");

			cipher.init(mode, keyFact.generateSecret(pbeSpec), defParams);

			return cipher;
		}

		private Cipher makePBECipherWithoutParam(string algorithm, int mode, char[] password, byte[] salt, int iterationCount)
		{
			PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, iterationCount);
			SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm, "BC");

			Cipher cipher = Cipher.getInstance(algorithm, "BC");

			cipher.init(mode, keyFact.generateSecret(pbeSpec));

			return cipher;
		}

		public virtual void testPBEHMac(string hmacName, byte[] output)
		{
			SecretKey key;
			byte[] @out;
			Mac mac;

			try
			{
				SecretKeyFactory fact = SecretKeyFactory.getInstance(hmacName, "BC");

				key = fact.generateSecret(new PBEKeySpec("hello".ToCharArray()));

				mac = Mac.getInstance(hmacName, "BC");
			}
			catch (Exception e)
			{
				fail("Failed - exception " + e.ToString(), e);
				return;
			}

			try
			{
				mac.init(key, new PBEParameterSpec(new byte[20], 100));
			}
			catch (Exception e)
			{
				fail("Failed - exception " + e.ToString(), e);
				return;
			}

			mac.reset();

			mac.update(message, 0, message.Length);

			@out = mac.doFinal();

			if (!Arrays.areEqual(@out, output))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}
		}

		public virtual void testPKCS12HMac(string hmacName, byte[] output)
		{
			SecretKey key;
			byte[] @out;
			Mac mac;

			try
			{
				mac = Mac.getInstance(hmacName, "BC");
			}
			catch (Exception e)
			{
				fail("Failed - exception " + e.ToString(), e);
				return;
			}

			try
			{
				mac.init(new PKCS12Key("hello".ToCharArray()), new PBEParameterSpec(new byte[20], 100));
			}
			catch (Exception e)
			{
				fail("Failed - exception " + e.ToString(), e);
				return;
			}

			mac.reset();

			mac.update(message, 0, message.Length);

			@out = mac.doFinal();

			if (!Arrays.areEqual(@out, output))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}
		}

		public virtual void testPBEonSecretKeyHmac(string hmacName, byte[] output)
		{
			SecretKey key;
			byte[] @out;
			Mac mac;

			try
			{
				SecretKeyFactory fact = SecretKeyFactory.getInstance(hmacName, "BC");

				key = fact.generateSecret(new PBEKeySpec("hello".ToCharArray(), new byte[20], 100, 160));

				mac = Mac.getInstance("HMAC-SHA1", "BC");
			}
			catch (Exception e)
			{
				fail("Failed - exception " + e.ToString(), e);
				return;
			}

			try
			{
				mac.init(key);
			}
			catch (Exception e)
			{
				fail("Failed - exception " + e.ToString(), e);
				return;
			}

			mac.reset();

			mac.update(message, 0, message.Length);

			@out = mac.doFinal();

			if (!Arrays.areEqual(@out, output))
			{
				fail("Failed - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(@out)));
			}
		}

		private void testCipherNameWithWrap(string name, string simpleName)
		{
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(new SecureRandom());
			SecretKey key = kg.generateKey();

			byte[] salt = new byte[] {unchecked((byte)0xc7), (byte)0x73, (byte)0x21, unchecked((byte)0x8c), (byte)0x7e, unchecked((byte)0xc8), unchecked((byte)0xee), unchecked((byte)0x99)};
			char[] password = new char[] {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

			PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, 20);
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
			SecretKeyFactory keyFac = SecretKeyFactory.getInstance(name);
			SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
			Cipher pbeEncryptCipher = Cipher.getInstance(name, "BC");

			pbeEncryptCipher.init(Cipher.WRAP_MODE, pbeKey, pbeParamSpec);

			byte[] symKeyBytes = pbeEncryptCipher.wrap(key);

			Cipher simpleCipher = Cipher.getInstance(simpleName, "BC");

			simpleCipher.init(Cipher.UNWRAP_MODE, pbeKey, pbeParamSpec);

			SecretKey unwrappedKey = (SecretKey)simpleCipher.unwrap(symKeyBytes, "AES", Cipher.SECRET_KEY);

			if (!Arrays.areEqual(unwrappedKey.getEncoded(), key.getEncoded()))
			{
				fail("key mismatch on unwrapping");
			}
		}

		public virtual void testNullSalt()
		{
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWITHSHAAND128BITAES-CBC-BC");
			Key key = skf.generateSecret(new PBEKeySpec("secret".ToCharArray()));

			Cipher cipher = Cipher.getInstance("PBEWITHSHAAND128BITAES-CBC-BC");

			try
			{
				cipher.init(Cipher.ENCRYPT_MODE, key, (AlgorithmParameterSpec)null);
				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isTrue("wrong message", "PBEKey requires parameters to specify salt".Equals(e.Message));
			}
		}

		public override void performTest()
		{
			byte[] input = Hex.decode("1234567890abcdefabcdef1234567890fedbca098765");

			//
			// DES
			//
			Cipher cEnc = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");

			cEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Hex.decode("30e69252758e5346"), "DES"), new IvParameterSpec(Hex.decode("7c1c1ab9c454a688")));

			byte[] @out = cEnc.doFinal(input);

			char[] password = new char[] {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

			Cipher cDec = makePBECipherUsingParam("PBEWithSHA1AndDES", Cipher.DECRYPT_MODE, password, Hex.decode("7d60435f02e9e0ae"), 2048);

			byte[] @in = cDec.doFinal(@out);

			if (!Arrays.areEqual(input, @in))
			{
				fail("DES failed");
			}

			cDec = makePBECipherWithoutParam("PBEWithSHA1AndDES", Cipher.DECRYPT_MODE, password, Hex.decode("7d60435f02e9e0ae"), 2048);

			@in = cDec.doFinal(@out);

			if (!Arrays.areEqual(input, @in))
			{
				fail("DES failed without param");
			}

			//
			// DESede
			//
			cEnc = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");

			cEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Hex.decode("732f2d33c801732b7206756cbd44f9c1c103ddd97c7cbe8e"), "DES"), new IvParameterSpec(Hex.decode("b07bf522c8d608b8")));

			@out = cEnc.doFinal(input);

			cDec = makePBECipherUsingParam("PBEWithSHAAnd3-KeyTripleDES-CBC", Cipher.DECRYPT_MODE, password, Hex.decode("7d60435f02e9e0ae"), 2048);

			@in = cDec.doFinal(@out);

			if (!Arrays.areEqual(input, @in))
			{
				fail("DESede failed");
			}

			//
			// 40Bit RC2
			//
			cEnc = Cipher.getInstance("RC2/CBC/PKCS7Padding", "BC");

			cEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Hex.decode("732f2d33c8"), "RC2"), new IvParameterSpec(Hex.decode("b07bf522c8d608b8")));

			@out = cEnc.doFinal(input);

			cDec = makePBECipherUsingParam("PBEWithSHAAnd40BitRC2-CBC", Cipher.DECRYPT_MODE, password, Hex.decode("7d60435f02e9e0ae"), 2048);

			@in = cDec.doFinal(@out);

			if (!Arrays.areEqual(input, @in))
			{
				fail("RC2 failed");
			}

			//
			// 128bit RC4
			//
			cEnc = Cipher.getInstance("RC4", "BC");

			cEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Hex.decode("732f2d33c801732b7206756cbd44f9c1"), "RC4"));

			@out = cEnc.doFinal(input);

			cDec = makePBECipherUsingParam("PBEWithSHAAnd128BitRC4", Cipher.DECRYPT_MODE, password, Hex.decode("7d60435f02e9e0ae"), 2048);

			@in = cDec.doFinal(@out);

			if (!Arrays.areEqual(input, @in))
			{
				fail("RC4 failed");
			}

			cDec = makePBECipherWithoutParam("PBEWithSHAAnd128BitRC4", Cipher.DECRYPT_MODE, password, Hex.decode("7d60435f02e9e0ae"), 2048);

			@in = cDec.doFinal(@out);

			if (!Arrays.areEqual(input, @in))
			{
				fail("RC4 failed without param");
			}

			for (int i = 0; i != pkcs12Tests.Length; i++)
			{
				pkcs12Tests[i].perform();
			}

			for (int i = 0; i != openSSLTests.Length; i++)
			{
				openSSLTests[i].perform();
			}

			testPKCS12Interop();

			testPBEHMac("PBEWithHMacSHA1", hMac1);
			testPBEHMac("PBEWithHMacRIPEMD160", hMac2);

			testPBEonSecretKeyHmac("PBKDF2WithHmacSHA1", hMac3);

			testCipherNameWithWrap("PBEWITHSHA256AND128BITAES-CBC-BC", "AES/CBC/PKCS5Padding");
			testCipherNameWithWrap("PBEWITHSHAAND40BITRC4", "RC4");
			testCipherNameWithWrap("PBEWITHSHAAND128BITRC4", "RC4");

			checkPBE("PBKDF2WithHmacSHA1", true, "f14687fc31a66e2f7cc01d0a65f687961bd27e20", "6f6579193d6433a3e4600b243bb390674f04a615");

			testPKCS12HMac("HMacSHA1", Hex.decode("bcc42174ccb04f425d9a5c8c4a95d6fd7c372911"));
			testPKCS12HMac("HMacSHA256", Hex.decode("e1ae77e2d1dcc56a8befa3867ea3ff8c2163b01885504379412e525b120bf9ce"));
			testPKCS12HMac("HMacSHA384", Hex.decode("1256a861351db2082f2ba827ca72cede54ee851f533962bba1fd97b500b6d6eb42aa4a51920aca0c817955feaf52d7f8"));
			testPKCS12HMac("HMacSHA512", Hex.decode("9090898971914cb2e65eb1b083f1cad1ce9a9d386f963a2e2ede965fbce0a7121526b5f8aed83f81db60b97ced0bc4b0c27cf23407028cc2f289957f607cec98"));
			testPKCS12HMac("HMacRIPEMD160", Hex.decode("cb1d8bdb6aca9e3fa8980d6eb41ab28a7eb2cfd6"));

			try
			{
				Mac mac = Mac.getInstance("HMacRIPEMD256", "BC");

				mac.init(new PKCS12Key("hello".ToCharArray()), new PBEParameterSpec(new byte[20], 100));
				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isTrue("wrong exception", "no PKCS12 mapping for HMAC: RIPEMD256/HMAC".Equals(e.Message));
			}

			testMixedKeyTypes();
			testNullSalt();
		}

		private void testPKCS12Interop()
		{
			const string algorithm = "PBEWithSHA256And192BitAES-CBC-BC";

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.spec.PBEKeySpec keySpec = new javax.crypto.spec.PBEKeySpec("foo123".toCharArray(), org.bouncycastle.util.encoders.Hex.decode("01020304050607080910"), 1024);
			PBEKeySpec keySpec = new PBEKeySpec("foo123".ToCharArray(), Hex.decode("01020304050607080910"), 1024);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.SecretKeyFactory fact = javax.crypto.SecretKeyFactory.getInstance(algorithm, "BC");
			SecretKeyFactory fact = SecretKeyFactory.getInstance(algorithm, "BC");

			BCPBEKey bcpbeKey = (BCPBEKey)fact.generateSecret(keySpec);

			Cipher c1 = Cipher.getInstance(algorithm, "BC");

			c1.init(Cipher.ENCRYPT_MODE, new PKCS12KeyWithParameters("foo123".ToCharArray(), Hex.decode("01020304050607080910"), 1024));

			Cipher c2 = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

			c2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(bcpbeKey.getEncoded(), "AES"), new IvParameterSpec(((ParametersWithIV)bcpbeKey.getParam()).getIV()));

			if (!Arrays.areEqual(Hex.decode("deadbeef"), c2.doFinal(c1.doFinal(Hex.decode("deadbeef")))))
			{
				fail("new key failed");
			}

			c1.init(Cipher.ENCRYPT_MODE, bcpbeKey);

			if (!Arrays.areEqual(Hex.decode("deadbeef"), c2.doFinal(c1.doFinal(Hex.decode("deadbeef")))))
			{
				fail("old key failed");
			}
		}

		private void checkPBE(string baseAlg, bool defIsUTF8, string utf8, string eightBit)
		{
			byte[] utf8K = Hex.decode(utf8);
			byte[] ascK = Hex.decode(eightBit);

			SecretKeyFactory f = SecretKeyFactory.getInstance(baseAlg, "BC");
			KeySpec ks1 = new PBEKeySpec("\u0141\u0142".ToCharArray(), new byte[20], 4096, 160);
			if (!Arrays.areEqual((defIsUTF8) ? utf8K : ascK, f.generateSecret(ks1).getEncoded()))
			{
				fail(baseAlg + " wrong PBKDF2 k1 key generated, got : " + StringHelper.NewString(Hex.encode(f.generateSecret(ks1).getEncoded())));
			}

			KeySpec ks2 = new PBEKeySpec("\u0041\u0042".ToCharArray(), new byte[20], 4096, 160);
			if (!Arrays.areEqual(ascK, f.generateSecret(ks2).getEncoded()))
			{
				fail(baseAlg + " wrong PBKDF2 k2 key generated");
			}
			f = SecretKeyFactory.getInstance(baseAlg + "AndUTF8", "BC");
			ks1 = new PBEKeySpec("\u0141\u0142".ToCharArray(), new byte[20], 4096, 160);
			if (!Arrays.areEqual(utf8K, f.generateSecret(ks1).getEncoded()))
			{
				fail(baseAlg + " wrong PBKDF2 k1 utf8 key generated");
			}

			ks2 = new PBEKeySpec("\u0041\u0042".ToCharArray(), new byte[20], 4096, 160);
			if (!Arrays.areEqual(ascK, f.generateSecret(ks2).getEncoded()))
			{
				fail(baseAlg + " wrong PBKDF2 k2 utf8 key generated");
			}
			f = SecretKeyFactory.getInstance(baseAlg + "And8BIT", "BC");
			ks1 = new PBEKeySpec("\u0141\u0142".ToCharArray(), new byte[20], 4096, 160);
			if (!Arrays.areEqual(ascK, f.generateSecret(ks1).getEncoded()))
			{
				fail(baseAlg + " wrong PBKDF2 k1 8bit key generated");
			}

			ks2 = new PBEKeySpec("\u0041\u0042".ToCharArray(), new byte[20], 4096, 160);
			if (!Arrays.areEqual(ascK, f.generateSecret(ks2).getEncoded()))
			{
				fail(baseAlg + " wrong PBKDF2 k2 8bit key generated");
			}
		}

		// for regression testing only - don't try this at home.
		public virtual void testMixedKeyTypes()
		{
			string provider = "BC";
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA1", provider);
			PBEKeySpec pbeks = new PBEKeySpec("password".ToCharArray(), Strings.toByteArray("salt"), 100, 128);
			SecretKey secretKey = skf.generateSecret(pbeks);
			PBEParameterSpec paramSpec = new PBEParameterSpec(pbeks.getSalt(), pbeks.getIterationCount());

			// in this case pbeSpec picked up from internal class representing key
			Cipher cipher = Cipher.getInstance("PBEWITHSHAAND128BITAES-CBC-BC", provider);

			try
			{
				cipher.init(Cipher.ENCRYPT_MODE, secretKey);
				fail("no exception");
			}
			catch (InvalidKeyException e)
			{
				isTrue("wrong exception", "Algorithm requires a PBE key suitable for PKCS12".Equals(e.Message));
			}
		}

		public override string getName()
		{
			return "PBETest";
		}


		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new PBETest());
		}
	}

}