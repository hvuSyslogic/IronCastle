using System;

namespace org.bouncycastle.cms.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;

	public class AllTests : TestCase
	{
		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("CMS tests");

			suite.addTest(NewCompressedDataTest.suite());
			suite.addTest(NewSignedDataTest.suite());
			suite.addTest(NewEnvelopedDataTest.suite());
			suite.addTest(NewAuthenticatedDataTest.suite());
			suite.addTest(NewAuthenticatedDataStreamTest.suite());
			suite.addTest(NewCompressedDataStreamTest.suite());
			suite.addTest(NewSignedDataStreamTest.suite());
			suite.addTest(NewEnvelopedDataStreamTest.suite());

			suite.addTest(MiscDataStreamTest.suite());
			suite.addTest(Rfc4134Test.suite());
			suite.addTest(ConverterTest.suite());

			suite.addTest(BcEnvelopedDataTest.suite());
			suite.addTest(BcSignedDataTest.suite());

			try
			{
				Cipher.getInstance("RSA", "SunJCE");

				suite.addTest(SunProviderTest.suite());
				suite.addTest(NullProviderTest.suite());
			}
			catch (Exception)
			{
				// ignore
			}

			return suite;
		}
	}

}