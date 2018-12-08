namespace org.bouncycastle.asn1.test
{

	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class KeyUsageTest : SimpleTest
	{
		public override string getName()
		{
			return "KeyUsage";
		}

		public override void performTest()
		{
			BitStringConstantTester.testFlagValueCorrect(0, KeyUsage.digitalSignature);
			BitStringConstantTester.testFlagValueCorrect(1, KeyUsage.nonRepudiation);
			BitStringConstantTester.testFlagValueCorrect(2, KeyUsage.keyEncipherment);
			BitStringConstantTester.testFlagValueCorrect(3, KeyUsage.dataEncipherment);
			BitStringConstantTester.testFlagValueCorrect(4, KeyUsage.keyAgreement);
			BitStringConstantTester.testFlagValueCorrect(5, KeyUsage.keyCertSign);
			BitStringConstantTester.testFlagValueCorrect(6, KeyUsage.cRLSign);
			BitStringConstantTester.testFlagValueCorrect(7, KeyUsage.encipherOnly);
			BitStringConstantTester.testFlagValueCorrect(8, KeyUsage.decipherOnly);

			if (!(new KeyUsage(KeyUsage.keyCertSign)).hasUsages(KeyUsage.keyCertSign))
			{
				fail("usages bit test failed 1");
			}

			if ((new KeyUsage(KeyUsage.cRLSign)).hasUsages(KeyUsage.keyCertSign))
			{
				fail("usages bit test failed 2");
			}

			if (!(new KeyUsage(KeyUsage.cRLSign | KeyUsage.decipherOnly)).hasUsages(KeyUsage.cRLSign | KeyUsage.decipherOnly))
			{
				fail("usages bit test failed 3");
			}

			if ((new KeyUsage(KeyUsage.cRLSign | KeyUsage.decipherOnly)).hasUsages(KeyUsage.cRLSign | KeyUsage.decipherOnly | KeyUsage.keyCertSign))
			{
				fail("usages bit test failed 4");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new KeyUsageTest());
		}
	}

}