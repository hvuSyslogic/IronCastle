namespace org.bouncycastle.est.test
{

	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	public class ESTTestSetup : TestSetup
	{
		public ESTTestSetup(Test test) : base(test)
		{
		}

		public virtual void setUp()
		{
			Security.addProvider(new BouncyCastleProvider());
		}

		public virtual void tearDown()
		{
			Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}

	}

}