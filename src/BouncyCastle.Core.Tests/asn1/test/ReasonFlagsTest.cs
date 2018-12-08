namespace org.bouncycastle.asn1.test
{

	using ReasonFlags = org.bouncycastle.asn1.x509.ReasonFlags;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class ReasonFlagsTest : SimpleTest
	{
		public override string getName()
		{
			return "ReasonFlags";
		}

		public override void performTest()
		{
			BitStringConstantTester.testFlagValueCorrect(0, ReasonFlags.unused);
			BitStringConstantTester.testFlagValueCorrect(1, ReasonFlags.keyCompromise);
			BitStringConstantTester.testFlagValueCorrect(2, ReasonFlags.cACompromise);
			BitStringConstantTester.testFlagValueCorrect(3, ReasonFlags.affiliationChanged);
			BitStringConstantTester.testFlagValueCorrect(4, ReasonFlags.superseded);
			BitStringConstantTester.testFlagValueCorrect(5, ReasonFlags.cessationOfOperation);
			BitStringConstantTester.testFlagValueCorrect(6, ReasonFlags.certificateHold);
			BitStringConstantTester.testFlagValueCorrect(7, ReasonFlags.privilegeWithdrawn);
			BitStringConstantTester.testFlagValueCorrect(8, ReasonFlags.aACompromise);
		}

		public static void Main(string[] args)
		{
			runTest(new ReasonFlagsTest());
		}
	}

}