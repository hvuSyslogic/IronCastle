using org.bouncycastle.jce.provider;

using System;

namespace org.bouncycastle.openpgp.test
{

	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class RegressionTest
	{
		public static Test[] tests = new Test[]
		{
			new BcPGPKeyRingTest(),
			new PGPKeyRingTest(),
			new BcPGPRSATest(),
			new PGPRSATest(),
			new BcPGPDSATest(),
			new PGPDSATest(),
			new BcPGPDSAElGamalTest(),
			new PGPDSAElGamalTest(),
			new BcPGPPBETest(),
			new PGPPBETest(),
			new PGPMarkerTest(),
			new PGPPacketTest(),
			new PGPArmoredTest(),
			new PGPSignatureTest(),
			new PGPClearSignedSignatureTest(),
			new PGPCompressionTest(),
			new PGPNoPrivateKeyTest(),
			new PGPECDSATest(),
			new PGPECDHTest(),
			new PGPECMessageTest(),
			new PGPParsingTest(),
			new SExprTest(),
			new ArmoredInputStreamTest(),
			new PGPUtilTest()
		};

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			for (int i = 0; i != tests.Length; i++)
			{
				TestResult result = tests[i].perform();
				JavaSystem.@out.println(result);
				if (result.getException() != null)
				{
					Console.WriteLine(result.getException().ToString());
					Console.Write(result.getException().StackTrace);
				}
			}
		}
	}


}