namespace org.bouncycastle.dvcs.test
{

	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	public class DVCSTestSetup : TestSetup
	{
		public DVCSTestSetup(Test test) : base(test)
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