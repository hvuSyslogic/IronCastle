using org.bouncycastle.jce.provider;

// Copyright (c) 2005 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
namespace org.bouncycastle.pkcs.test
{

	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;

	public class BCTestSetup : TestSetup
	{
		public BCTestSetup(Test test) : base(test)
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