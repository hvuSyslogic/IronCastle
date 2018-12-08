namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using Assert = junit.framework.Assert;
	using TestCase = junit.framework.TestCase;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Test cases for the use of NewHope (NH) with the BCPQC provider.
	/// </summary>
	public class NewHopeTest : TestCase
	{
		public virtual void setUp()
		{
			if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
			{
				Security.addProvider(new BouncyCastlePQCProvider());
			}
		}

		public virtual void testKeyExchange()
		{
			SecureRandom aliceRand = new SecureRandom();
			SecureRandom bobRand = new SecureRandom();

			for (int i = 0; i < 1000; ++i)
			{
				KeyPairGenerator kpGen = KeyPairGenerator.getInstance("NH", "BCPQC");

				kpGen.initialize(1024, aliceRand);

				KeyPair aliceKp = kpGen.generateKeyPair();

				KeyAgreement bobAgree = KeyAgreement.getInstance("NH", "BCPQC");

				// responder has no private key, but needs a random number source.
				bobAgree.init(null, bobRand);

				Key bobSend = bobAgree.doPhase(aliceKp.getPublic(), true);

				KeyAgreement aliceAgree = KeyAgreement.getInstance("NH", "BCPQC");

				// initiator uses both private key
				aliceAgree.init(aliceKp.getPrivate());

				// and recipient's public key.
				aliceAgree.doPhase(bobSend, true);

				Assert.assertTrue("value mismatch", Arrays.areEqual(aliceAgree.generateSecret(), bobAgree.generateSecret()));
			}
		}
	}

}