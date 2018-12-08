namespace org.bouncycastle.jce.provider.test
{


	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using IEKeySpec = org.bouncycastle.jce.spec.IEKeySpec;
	using IESParameterSpec = org.bouncycastle.jce.spec.IESParameterSpec;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// test for ECIES - Elliptic Curve Integrated Encryption Scheme
	/// </summary>
	public class IESTest : SimpleTest
	{
		private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
		private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

		public IESTest()
		{
		}

		public override string getName()
		{
			return "IES";
		}

		public override void performTest()
		{
			KeyPairGenerator g = KeyPairGenerator.getInstance("ECIES", "BC");

			X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
			ECParameterSpec ecSpec = new ECParameterSpec(x9.getCurve(), x9.getG(),x9.getN(), x9.getH());

			g.initialize(ecSpec, new SecureRandom());

			Cipher c1 = Cipher.getInstance("ECIES", "BC");
			Cipher c2 = Cipher.getInstance("ECIES", "BC");

			doTest(g, c1, c2);

			g = KeyPairGenerator.getInstance("ECIES", "BC");

			g.initialize(192, new SecureRandom());

			doTest(g, c1, c2);

			g = KeyPairGenerator.getInstance("ECIES", "BC");

			g.initialize(239, new SecureRandom());

			doTest(g, c1, c2);

			g = KeyPairGenerator.getInstance("ECIES", "BC");

			g.initialize(256, new SecureRandom());

			doTest(g, c1, c2);

			doDefTest(g, c1, c2);

			DHParameterSpec dhParams = new DHParameterSpec(p512, g512);

			c1 = Cipher.getInstance("IES", "BC");
			c2 = Cipher.getInstance("IES", "BC");

			g = KeyPairGenerator.getInstance("DH", "BC");

			g.initialize(dhParams);

			doTest(g, c1, c2);

			doDefTest(g, c1, c2);
		}

		public virtual void doTest(KeyPairGenerator g, Cipher c1, Cipher c2)
		{
			//
			// a side
			//
			KeyPair aKeyPair = g.generateKeyPair();
			PublicKey aPub = aKeyPair.getPublic();
			PrivateKey aPriv = aKeyPair.getPrivate();

			//
			// b side
			//
			KeyPair bKeyPair = g.generateKeyPair();
			PublicKey bPub = bKeyPair.getPublic();
			PrivateKey bPriv = bKeyPair.getPrivate();

			//
			// stream test
			//

			IEKeySpec c1Key = new IEKeySpec(aPriv, bPub);
			IEKeySpec c2Key = new IEKeySpec(bPriv, aPub);

			byte[] d = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
			byte[] e = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};

			IESParameterSpec param = new IESParameterSpec(d, e, 128);

			c1.init(Cipher.ENCRYPT_MODE, c1Key, param);

			c2.init(Cipher.DECRYPT_MODE, c2Key, param);

			byte[] message = Hex.decode("1234567890abcdef");

			int estLen1 = c1.getOutputSize(message.Length);

			byte[] out1 = c1.doFinal(message, 0, message.Length);

			if (estLen1 < out1.Length)
			{
				fail("output size incorrect");
			}

			int estLen2 = c2.getOutputSize(out1.Length);

			byte[] out2 = c2.doFinal(out1, 0, out1.Length);

			if (estLen2 < out2.Length)
			{
				fail("output size incorrect");
			}

			if (!areEqual(out2, message))
			{
				fail("stream cipher test failed");
			}
		}

		public virtual void doDefTest(KeyPairGenerator g, Cipher c1, Cipher c2)
		{
			//
			// a side
			//
			KeyPair aKeyPair = g.generateKeyPair();
			PublicKey aPub = aKeyPair.getPublic();
			PrivateKey aPriv = aKeyPair.getPrivate();

			//
			// b side
			//
			KeyPair bKeyPair = g.generateKeyPair();
			PublicKey bPub = bKeyPair.getPublic();
			PrivateKey bPriv = bKeyPair.getPrivate();

			//
			// stream test
			//
			IEKeySpec c1Key = new IEKeySpec(aPriv, bPub);
			IEKeySpec c2Key = new IEKeySpec(bPriv, aPub);

			c1.init(Cipher.ENCRYPT_MODE, c1Key);

			AlgorithmParameters param = c1.getParameters();

			c2.init(Cipher.DECRYPT_MODE, c2Key, param);

			byte[] message = Hex.decode("1234567890abcdef");

			int estLen1 = c1.getOutputSize(message.Length);

			byte[] out1 = c1.doFinal(message, 0, message.Length);

			if (estLen1 < out1.Length)
			{
				fail("output size incorrect");
			}

			int estLen2 = c2.getOutputSize(out1.Length);
			byte[] out2 = c2.doFinal(out1, 0, out1.Length);

			if (estLen2 < out2.Length)
			{
				fail("output size incorrect");
			}

			if (!areEqual(out2, message))
			{
				fail("stream cipher test failed");
			}

			//
			// int doFinal
			//
			int len1 = c1.doFinal(message, 0, message.Length, out1, 0);

			if (len1 != out1.Length)
			{
				fail("encryption length wrong");
			}

			int len2 = c2.doFinal(out1, 0, out1.Length, out2, 0);

			if (len2 != out2.Length)
			{
				fail("decryption length wrong");
			}

			if (!areEqual(out2, message))
			{
				fail("stream cipher test failed");
			}

			//
			// int doFinal with update
			//
			len1 = c1.update(message, 0, 2, out1, 0);

			len1 += c1.doFinal(message, 2, message.Length - 2, out1, len1);

			if (len1 != out1.Length)
			{
				fail("update encryption length wrong");
			}

			len2 = c2.update(out1, 0, 2, out2, 0);

			len2 += c2.doFinal(out1, 2, out1.Length - 2, out2, len2);

			if (len2 != out2.Length)
			{
				fail("update decryption length wrong");
			}

			if (!areEqual(out2, message))
			{
				fail("update stream cipher test failed");
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new IESTest());
		}
	}

}