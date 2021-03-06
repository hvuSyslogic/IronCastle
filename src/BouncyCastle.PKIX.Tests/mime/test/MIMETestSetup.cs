﻿namespace org.bouncycastle.mime.test
{

	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	public class MIMETestSetup : TestSetup
	{
		public MIMETestSetup(Test test) : base(test)
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