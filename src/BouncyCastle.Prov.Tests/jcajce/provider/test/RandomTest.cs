namespace org.bouncycastle.jcajce.provider.test
{

	using Assert = junit.framework.Assert;
	using TestCase = junit.framework.TestCase;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	public class RandomTest : TestCase
	{
		public virtual void testCheckRandom()
		{
			SecureRandom random = SecureRandom.getInstance("DEFAULT", new BouncyCastleProvider());

			byte[] rng = new byte[20];

			random.nextBytes(rng);

			Assert.assertTrue(checkNonConstant(rng));
		}

		public virtual void testCheckNonceIVRandom()
		{
			SecureRandom random = SecureRandom.getInstance("NONCEANDIV", new BouncyCastleProvider());

			byte[] rng = new byte[20];

			random.nextBytes(rng);

			Assert.assertTrue(checkNonConstant(rng));
		}

		private bool checkNonConstant(byte[] data)
		{
			for (int i = 1; i != data.Length; i++)
			{
				if (data[i] != data[i - 1])
				{
					return true;
				}
			}

			return false;
		}
	}

}