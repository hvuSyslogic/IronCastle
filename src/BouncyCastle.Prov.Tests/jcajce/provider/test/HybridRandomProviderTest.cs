namespace org.bouncycastle.jcajce.provider.test
{

	using TestCase = junit.framework.TestCase;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	public class HybridRandomProviderTest : TestCase
	{
		public virtual void testCheckForStackOverflow()
		{
			Security.insertProviderAt(new BouncyCastleProvider(), 1);
			new SecureRandom("not so random bytes".GetBytes());
		}
	}

}