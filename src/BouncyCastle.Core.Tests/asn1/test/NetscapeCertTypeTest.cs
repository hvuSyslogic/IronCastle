namespace org.bouncycastle.asn1.test
{

	using NetscapeCertType = org.bouncycastle.asn1.misc.NetscapeCertType;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class NetscapeCertTypeTest : SimpleTest
	{
		public override string getName()
		{
			return "NetscapeCertType";
		}

		public override void performTest()
		{
			BitStringConstantTester.testFlagValueCorrect(0, NetscapeCertType.sslClient);
			BitStringConstantTester.testFlagValueCorrect(1, NetscapeCertType.sslServer);
			BitStringConstantTester.testFlagValueCorrect(2, NetscapeCertType.smime);
			BitStringConstantTester.testFlagValueCorrect(3, NetscapeCertType.objectSigning);
			BitStringConstantTester.testFlagValueCorrect(4, NetscapeCertType.reserved);
			BitStringConstantTester.testFlagValueCorrect(5, NetscapeCertType.sslCA);
			BitStringConstantTester.testFlagValueCorrect(6, NetscapeCertType.smimeCA);
			BitStringConstantTester.testFlagValueCorrect(7, NetscapeCertType.objectSigningCA);
		}

		public static void Main(string[] args)
		{
			runTest(new NetscapeCertTypeTest());
		}
	}

}