namespace org.bouncycastle.jce.provider.test
{

	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class GOST3410KeyPairTest : SimpleTest
	{
		private void gost2012MismatchTest()
		{
			KeyPairGenerator keyPair = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");

			keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"));

			KeyPair kp = keyPair.generateKeyPair();

			testWrong256(kp);

			keyPair = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");

			keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetB"));

			kp = keyPair.generateKeyPair();

			testWrong256(kp);

			keyPair = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");

			keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetC"));

			kp = keyPair.generateKeyPair();

			testWrong256(kp);

			keyPair = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");

			keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"));

			kp = keyPair.generateKeyPair();

			testWrong512(kp);
		}

		private void testWrong512(KeyPair kp)
		{
			Signature sig;
			sig = Signature.getInstance("ECGOST3410-2012-512", "BC");

			try
			{
				sig.initSign(kp.getPrivate());

				fail("no exception");
			}
			catch (InvalidKeyException e)
			{
				isEquals("key too weak for ECGOST-2012-512", e.Message);
			}

			try
			{
				sig.initVerify(kp.getPublic());
				fail("no exception");
			}
			catch (InvalidKeyException e)
			{
				isEquals("key too weak for ECGOST-2012-512", e.Message);
			}
		}

		private void testWrong256(KeyPair kp)
		{
			Signature sig = Signature.getInstance("ECGOST3410-2012-256", "BC");

			try
			{
				sig.initSign(kp.getPrivate());
				fail("no exception");
			}
			catch (InvalidKeyException e)
			{
				isEquals("key out of range for ECGOST-2012-256", e.Message);
			}

			try
			{
				sig.initVerify(kp.getPublic());
				fail("no exception");
			}
			catch (InvalidKeyException e)
			{
				isEquals("key out of range for ECGOST-2012-256", e.Message);
			}
		}

		private BigInteger[] decode(byte[] encoding)
		{
			byte[] r = new byte[32];
			byte[] s = new byte[32];

			JavaSystem.arraycopy(encoding, 0, s, 0, 32);

			JavaSystem.arraycopy(encoding, 32, r, 0, 32);

			BigInteger[] sig = new BigInteger[2];

			sig[0] = new BigInteger(1, r);
			sig[1] = new BigInteger(1, s);

			return sig;
		}

		private object serializeDeserialize(object o)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ObjectOutputStream oOut = new ObjectOutputStream(bOut);

			oOut.writeObject(o);
			oOut.close();

			ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

			return oIn.readObject();
		}

		public override string getName()
		{
			return "GOST3410/ECGOST3410/ECGOST3410 2012";
		}

		public override void performTest()
		{
			gost2012MismatchTest();
		}

		public virtual byte[] toByteArray(string input)
		{
			byte[] bytes = new byte[input.Length];

			for (int i = 0; i != bytes.Length; i++)
			{
				bytes[i] = (byte)input[i];
			}

			return bytes;
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new GOST3410KeyPairTest());
		}
	}

}