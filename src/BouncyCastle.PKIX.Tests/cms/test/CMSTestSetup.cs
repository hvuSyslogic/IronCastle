using org.bouncycastle.jce.provider;

namespace org.bouncycastle.cms.test
{
	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;

	public class CMSTestSetup : TestSetup
	{
		public CMSTestSetup(Test test) : base(test)
		{
		}

		public virtual void setUp()
		{
			Security.addProvider(new BouncyCastleProvider());
		}

		public virtual void tearDown()
		{
			Security.removeProvider("BC");
		}
	}

}