namespace org.bouncycastle.jce.provider.test
{


	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class SlotTwoTest : SimpleTest
	{
		internal byte[] plainData = "abcdefghijklmnopqrstuvwxyz".getBytes();

		public override string getName()
		{
			return "SlotTwo";
		}

		public override void performTest()
		{
			Security.removeProvider("BC");
			Security.insertProviderAt(new BouncyCastleProvider(), 2);

			KeyGenerator keyGen = KeyGenerator.getInstance("DESede", "BC");

			keyGen.init(new SecureRandom());

			Key key = keyGen.generateKey();

			testDesEde(key, "ECB", "PKCS7Padding");
			testDesEde(key, "CBC", "PKCS7Padding");
			testDesEde(key, "CTR", "NoPadding");
			testDesEde(key, "CTR", "PKCS7Padding");
			testDesEde(key, "OFB", "PKCS7Padding");
			testDesEde(key, "CFB", "PKCS7Padding");

			Security.removeProvider("BC");
			Security.addProvider(new BouncyCastleProvider());
		}

		private void testDesEde(Key key, string mode, string padding)
		{
			Cipher encrypt = Cipher.getInstance("DESede/" + mode + "/" + padding, "BC");
			Cipher decrypt = Cipher.getInstance("DESede/" + mode + "/" + padding);

			if (!decrypt.getProvider().getName().Equals("BC"))
			{
				fail("BC provider not returned for DESede/" + mode + "/" + padding + " got " + decrypt.getProvider().getName());
			}

			encrypt.init(Cipher.ENCRYPT_MODE, key);

			byte[] encryptedBytes = encrypt.doFinal(plainData);
			byte[] ivBytes = encrypt.getIV();

			if (ivBytes != null)
			{
				IvParameterSpec ivp = new IvParameterSpec(ivBytes);

				decrypt.init(Cipher.DECRYPT_MODE, key, ivp);
			}
			else
			{
				decrypt.init(Cipher.DECRYPT_MODE, key);
			}

			byte[] plainBytes = decrypt.doFinal(encryptedBytes, 0, encryptedBytes.Length);

			if (!areEqual(plainData, plainBytes))
			{
				fail("decryption test failed.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new SlotTwoTest());
		}
	}

}